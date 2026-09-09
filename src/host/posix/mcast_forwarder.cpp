/*
 *    Copyright (c) 2026, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

#define OTBR_LOG_TAG "MCAST"

#include "host/posix/mcast_forwarder.hpp"

#include <errno.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <string.h>

#include "common/logging.hpp"

namespace otbr {

namespace {

// ICMPv6 types (RFC 2710, RFC 3810)
constexpr uint8_t kMldv1Report = 131;
constexpr uint8_t kMldv1Done   = 132;
constexpr uint8_t kMldv2Report = 143;

// MLDv2 multicast address record types (RFC 3810 §5.2.12)
constexpr uint8_t kModeIsInclude   = 1;
constexpr uint8_t kModeIsExclude   = 2;
constexpr uint8_t kChangeToInclude = 3;
constexpr uint8_t kChangeToExclude = 4;
constexpr uint8_t kAllowNewSources = 5;
constexpr uint8_t kBlockOldSources = 6;

constexpr size_t kIp6HeaderSize       = 40;
constexpr size_t kIp6ExtHeaderUnit    = 8;
constexpr size_t kMldv1Size           = 24; // ICMPv6 header (8) + multicast address (16)
constexpr size_t kMldv2HeaderSize     = 8;  // ICMPv6 header (4) + reserved (2) + number of records (2)
constexpr size_t kMldv2RecordHeadSize = 20; // type (1) + aux data len (1) + number of sources (2) + address (16)
constexpr size_t kIp6AddressSize      = 16;
constexpr size_t kMldv2AuxDataUnit    = 4;

// Rate limits for forwarded multicast. Thread group traffic (Matter
// groupcast) is a few packets per second at most; these leave headroom
// while keeping a storm from either side well below what a mesh can absorb.
constexpr McastRateLimiter::Config kRateLimits = {
    /* mPerGroupRatePerSecond */ 20,
    /* mPerGroupBurst */ 40,
    /* mTotalRatePerSecond */ 100,
    /* mTotalBurst */ 200,
    /* mMaxGroups */ 32,
};

uint16_t ReadUint16(const uint8_t *aBuffer)
{
    return static_cast<uint16_t>((aBuffer[0] << 8) | aBuffer[1]);
}

Ip6Address ReadAddress(const uint8_t *aBuffer)
{
    Ip6Address address;

    memcpy(address.m8, aBuffer, kIp6AddressSize);
    return address;
}

// Accepts IPv6 packets whose transport is ICMPv6, directly or behind the
// Hop-by-Hop header MLD messages carry for the Router Alert option. The
// ICMPv6 type is checked in userspace.
const struct bpf_insn kIcmp6FilterNull[] = {
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4),                      // IPv6 version nibble
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),                  //
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 0, 6),            // not IPv6 -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4 + 6),                  // next header
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 3, 0),  // ICMPv6 -> accept
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_HOPOPTS, 0, 3), // not Hop-by-Hop -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4 + 40),                 // Hop-by-Hop next header
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 1),  //
    BPF_STMT(BPF_RET | BPF_K, 0xffffffff),                      // accept
    BPF_STMT(BPF_RET | BPF_K, 0),                               // drop
};

const struct bpf_insn kIcmp6FilterEthernet[] = {
    BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                     // EtherType
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 0, 6),          // not IPv6 -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14 + 6),                 // next header
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 3, 0),  // ICMPv6 -> accept
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_HOPOPTS, 0, 3), // not Hop-by-Hop -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14 + 40),                // Hop-by-Hop next header
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 1),  //
    BPF_STMT(BPF_RET | BPF_K, 0xffffffff),                      // accept
    BPF_STMT(BPF_RET | BPF_K, 0),                               // drop
};

// Accepts IPv6 packets to a multicast destination of admin-local scope or
// larger, the only ones a Backbone Router carries. The Thread interface is a
// tunnel (DLT_NULL, 4-byte family header).
const struct bpf_insn kForwardableMulticastFilterNull[] = {
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4),           // IPv6 version nibble
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),       //
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 0, 6), // not IPv6 -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4 + 24),      // destination[0]
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xff, 0, 4), // not multicast -> drop
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4 + 25),      // destination[1]: flags | scope
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0f),       //
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x04, 0, 1), // scope < admin-local -> drop
    BPF_STMT(BPF_RET | BPF_K, 0xffffffff),           // accept
    BPF_STMT(BPF_RET | BPF_K, 0),                    // drop
};

template <size_t N> otbrError SetFilter(BpfTap &aTap, const struct bpf_insn (&aInsns)[N])
{
    return aTap.SetFilter(aInsns, N);
}

} // namespace

// Odr-used (chrono takes them by reference); C++11 needs the definitions.
constexpr uint32_t McastForwarder::kBackboneListenerTimeoutSec;
constexpr uint32_t McastForwarder::kExpireIntervalSec;
constexpr uint32_t McastForwarder::kReportIntervalSec;
constexpr uint32_t McastForwarder::kDedupWindowMs;
constexpr size_t   McastForwarder::kDedupEntries;
constexpr size_t   McastForwarder::kMaxFrameSize;

McastForwarder::McastForwarder(const std::string &aThreadIfName, const std::string &aBackboneIfName)
    : mThreadIfName(aThreadIfName)
    , mBackboneIfName(aBackboneIfName)
    , mEnabled(false)
    , mHasBackboneMac(false)
    , mDedup(kDedupWindowMs, kDedupEntries)
    , mRateLimiter(kRateLimits)
    , mNextExpire(Clock::now())
    , mNextReport(Clock::now())
{
    memset(mBackboneMac, 0, sizeof(mBackboneMac));
}

McastForwarder::~McastForwarder(void)
{
    Disable();
}

void McastForwarder::HandleBackboneRouterStateChange(otBackboneRouterState aState)
{
    otbrLogInfo("Backbone Router state: %d", aState);

    if (aState == OT_BACKBONE_ROUTER_STATE_PRIMARY)
    {
        Enable();
    }
    else
    {
        Disable();
    }
}

void McastForwarder::HandleBackboneMulticastListenerEvent(otBackboneRouterMulticastListenerEvent aEvent,
                                                          const Ip6Address                      &aAddress)
{
    switch (aEvent)
    {
    case OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ADDED:
        mThreadListeners.insert(aAddress);
        otbrLogInfo("Thread listener added: %s (%zu groups)", aAddress.ToString().c_str(), mThreadListeners.size());
        break;
    case OT_BACKBONE_ROUTER_MULTICAST_LISTENER_REMOVED:
        mThreadListeners.erase(aAddress);
        otbrLogInfo("Thread listener removed: %s (%zu groups)", aAddress.ToString().c_str(), mThreadListeners.size());
        break;
    }
}

void McastForwarder::Enable(void)
{
    VerifyOrExit(!mEnabled);
    mEnabled = true;
    otbrLogNotice("Enabled: thread %s, backbone %s (thread->backbone forwarding, backbone->thread not yet)",
                  mThreadIfName.c_str(), mBackboneIfName.empty() ? "(none)" : mBackboneIfName.c_str());

    OpenBackboneTap();
    OpenThreadTap();

exit:
    return;
}

void McastForwarder::OpenBackboneTap(void)
{
    otbrError error;

    VerifyOrExit(!mBackboneIfName.empty(),
                 otbrLogWarning("No backbone interface; nothing is forwarded and backbone listeners are unknown"));
    VerifyOrExit(ReadBackboneMac(),
                 otbrLogWarning("No link address on %s; nothing is forwarded to it", mBackboneIfName.c_str()));

    // The host itself may be a listener, so its own MLD reports count too.
    error = mBackboneTap.Open(mBackboneIfName, /* aSeeSent */ true);
    VerifyOrExit(error == OTBR_ERROR_NONE, otbrLogWarning("Cannot attach to %s", mBackboneIfName.c_str()));

    switch (mBackboneTap.GetDataLinkType())
    {
    case DLT_NULL:
        error = SetFilter(mBackboneTap, kIcmp6FilterNull);
        break;
    default:
        error = SetFilter(mBackboneTap, kIcmp6FilterEthernet);
        break;
    }
    if (error != OTBR_ERROR_NONE)
    {
        otbrLogWarning("Cannot install the MLD filter on %s: %s", mBackboneIfName.c_str(), strerror(errno));
        mBackboneTap.Close();
    }

exit:
    return;
}

void McastForwarder::OpenThreadTap(void)
{
    otbrError error;

    // Inbound only: the packets the Thread stack hands to the host, which
    // is everything it received from the mesh (it runs the interface in
    // multicast-promiscuous mode), never what the host sent it.
    error = mThreadTap.Open(mThreadIfName, /* aSeeSent */ false);
    VerifyOrExit(
        error == OTBR_ERROR_NONE,
        otbrLogWarning("Cannot attach to %s; nothing is forwarded from the Thread network", mThreadIfName.c_str()));
    VerifyOrExit(mThreadTap.GetDataLinkType() == DLT_NULL,
                 otbrLogWarning("%s is not a tunnel interface (dlt %u); nothing is forwarded from it",
                                mThreadIfName.c_str(), mThreadTap.GetDataLinkType()));

    error = SetFilter(mThreadTap, kForwardableMulticastFilterNull);
    VerifyOrExit(error == OTBR_ERROR_NONE, otbrLogWarning("Cannot install the multicast filter on %s: %s",
                                                          mThreadIfName.c_str(), strerror(errno)));
    ExitNow();

exit:
    if (error != OTBR_ERROR_NONE)
    {
        mThreadTap.Close();
    }
}

void McastForwarder::Disable(void)
{
    VerifyOrExit(mEnabled);
    mEnabled = false;
    mThreadTap.Close();
    mBackboneTap.Close();
    mBackboneListeners.clear();
    ReportCounters();
    otbrLogNotice("Disabled");

exit:
    return;
}

bool McastForwarder::ReadBackboneMac(void)
{
    struct ifaddrs *addresses = nullptr;

    mHasBackboneMac = false;
    VerifyOrExit(getifaddrs(&addresses) == 0);

    for (struct ifaddrs *ifa = addresses; ifa != nullptr; ifa = ifa->ifa_next)
    {
        const struct sockaddr_dl *link;

        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_LINK || mBackboneIfName != ifa->ifa_name)
        {
            continue;
        }
        link = reinterpret_cast<const struct sockaddr_dl *>(ifa->ifa_addr);
        if (link->sdl_alen == McastForwardPolicy::kMacSize)
        {
            memcpy(mBackboneMac, LLADDR(link), McastForwardPolicy::kMacSize);
            mHasBackboneMac = true;
            break;
        }
    }
    freeifaddrs(addresses);

exit:
    return mHasBackboneMac;
}

bool McastForwarder::IsTrackedGroup(const Ip6Address &aGroup)
{
    return aGroup.IsMulticast() && aGroup.GetScope() > Ip6Address::kLinkLocalScope;
}

bool McastForwarder::ParseMld(const uint8_t *aPacket, size_t aLength, std::vector<MldRecord> &aRecords)
{
    bool           isMld  = false;
    size_t         offset = kIp6HeaderSize;
    uint8_t        nextHeader;
    const uint8_t *icmp;
    size_t         icmpLength;

    aRecords.clear();

    VerifyOrExit(aLength >= kIp6HeaderSize && (aPacket[0] >> 4) == 6);
    nextHeader = aPacket[6];

    // MLD messages carry a Hop-by-Hop header with the Router Alert option.
    while (nextHeader == IPPROTO_HOPOPTS || nextHeader == IPPROTO_DSTOPTS || nextHeader == IPPROTO_ROUTING)
    {
        VerifyOrExit(offset + kIp6ExtHeaderUnit <= aLength);
        nextHeader = aPacket[offset];
        offset += (static_cast<size_t>(aPacket[offset + 1]) + 1) * kIp6ExtHeaderUnit;
    }
    VerifyOrExit(nextHeader == IPPROTO_ICMPV6 && offset + 4 <= aLength);

    icmp       = aPacket + offset;
    icmpLength = aLength - offset;

    switch (icmp[0])
    {
    case kMldv1Report:
    case kMldv1Done:
        VerifyOrExit(icmpLength >= kMldv1Size);
        aRecords.push_back({ReadAddress(icmp + 8), icmp[0] == kMldv1Report});
        isMld = true;
        break;

    case kMldv2Report:
    {
        uint16_t count;
        size_t   pos = kMldv2HeaderSize;

        VerifyOrExit(icmpLength >= kMldv2HeaderSize);
        count = ReadUint16(icmp + 6);

        for (uint16_t i = 0; i < count; i++)
        {
            uint8_t    type;
            uint8_t    auxLength;
            uint16_t   sources;
            Ip6Address group;

            VerifyOrExit(pos + kMldv2RecordHeadSize <= icmpLength);
            type      = icmp[pos];
            auxLength = icmp[pos + 1];
            sources   = ReadUint16(icmp + pos + 2);
            group     = ReadAddress(icmp + pos + 4);

            // Source-specific detail is folded into "any source": a record that
            // leaves the listener interested in some source is a join, one that
            // leaves it interested in none is a leave.
            switch (type)
            {
            case kModeIsExclude:
            case kChangeToExclude:
                aRecords.push_back({group, true});
                break;
            case kModeIsInclude:
            case kAllowNewSources:
                if (sources > 0)
                {
                    aRecords.push_back({group, true});
                }
                break;
            case kChangeToInclude:
                if (sources == 0)
                {
                    aRecords.push_back({group, false});
                }
                break;
            case kBlockOldSources:
                // An empty BLOCK record has no meaning in RFC 3810, but it is
                // how macOS reports the last socket leaving a group.
                if (sources == 0)
                {
                    aRecords.push_back({group, false});
                }
                break;
            default:
                break;
            }

            pos += kMldv2RecordHeadSize + sources * kIp6AddressSize + auxLength * kMldv2AuxDataUnit;
        }
        isMld = true;
        break;
    }

    default:
        break;
    }

exit:
    if (!isMld)
    {
        aRecords.clear();
    }
    return isMld;
}

void McastForwarder::HandleMldFrame(const uint8_t *aFrame, size_t aLength)
{
    size_t                 linkHeader = mBackboneTap.GetLinkHeaderLength();
    std::vector<MldRecord> records;

    VerifyOrExit(aLength > linkHeader);
    VerifyOrExit(ParseMld(aFrame + linkHeader, aLength - linkHeader, records));
    HandleMldRecords(records);

exit:
    return;
}

void McastForwarder::HandleMldRecords(const std::vector<MldRecord> &aRecords)
{
    for (const MldRecord &record : aRecords)
    {
        otbrLogDebug("MLD %s %s", record.mIsJoin ? "join" : "leave", record.mGroup.ToString().c_str());

        // A report batches records for every group whose state changed,
        // link-local ones included; skip those without giving up on the rest.
        if (!IsTrackedGroup(record.mGroup))
        {
            continue;
        }

        if (record.mIsJoin)
        {
            bool isNew = mBackboneListeners.find(record.mGroup) == mBackboneListeners.end();

            mBackboneListeners[record.mGroup] = Clock::now();
            if (isNew)
            {
                otbrLogInfo("Backbone listener added: %s (%zu groups)", record.mGroup.ToString().c_str(),
                            mBackboneListeners.size());
            }
        }
        else if (mBackboneListeners.erase(record.mGroup) > 0)
        {
            otbrLogInfo("Backbone listener removed: %s (%zu groups)", record.mGroup.ToString().c_str(),
                        mBackboneListeners.size());
        }
    }
}

void McastForwarder::HandleThreadFrame(const uint8_t *aFrame, size_t aLength)
{
    size_t linkHeader = mThreadTap.GetLinkHeaderLength();

    VerifyOrExit(aLength > linkHeader);
    HandleThreadPacket(aFrame + linkHeader, aLength - linkHeader, Clock::now());

exit:
    return;
}

void McastForwarder::HandleThreadPacket(const uint8_t *aPacket, size_t aLength, Timepoint aNow)
{
    McastForwardPolicy::Verdict verdict;
    Ip6Address                  group;
    uint8_t                     frame[kMaxFrameSize];
    size_t                      frameLength;
    otbrError                   error;

    mThreadToBackbone.mReceived++;

    verdict = McastForwardPolicy::Check(aPacket, aLength);
    if (verdict != McastForwardPolicy::kForward)
    {
        mThreadToBackbone.mRejected++;
        otbrLogDebug("thread->backbone: %s: %s", McastForwardPolicy::VerdictToString(verdict),
                     McastForwardPolicy::GetDestination(aPacket).ToString().c_str());
        ExitNow();
    }

    if (mDedup.Check(McastDedupCache::Fingerprint(aPacket, aLength), aNow))
    {
        mThreadToBackbone.mDuplicates++;
        ExitNow();
    }

    group = McastForwardPolicy::GetDestination(aPacket);
    if (!mRateLimiter.Allow(group, aNow))
    {
        mThreadToBackbone.mRateLimited++;
        ExitNow();
    }

    // Build the frame with the hop limit already decremented.
    frameLength = McastForwardPolicy::BuildEthernetFrame(aPacket, aLength, mBackboneMac, frame, sizeof(frame));
    VerifyOrExit(frameLength > 0, mThreadToBackbone.mRejected++);
    McastForwardPolicy::DecrementHopLimit(frame + McastForwardPolicy::kEthernetHeaderSize);

    error = mBackboneTap.Write(frame, frameLength);
    if (error != OTBR_ERROR_NONE)
    {
        mThreadToBackbone.mErrors++;
        otbrLogDebug("thread->backbone: write to %s failed: %s", mBackboneIfName.c_str(),
                     error == OTBR_ERROR_INVALID_STATE ? "not attached" : strerror(errno));
        ExitNow();
    }

    mThreadToBackbone.mForwarded++;
    otbrLogDebug("thread->backbone: forwarded %s -> %s (%zu bytes)",
                 McastForwardPolicy::GetSource(aPacket).ToString().c_str(), group.ToString().c_str(), aLength);

exit:
    return;
}

void McastForwarder::ExpireBackboneListeners(void)
{
    Timepoint now = Clock::now();

    for (auto it = mBackboneListeners.begin(); it != mBackboneListeners.end();)
    {
        if (now - it->second > Seconds(kBackboneListenerTimeoutSec))
        {
            otbrLogInfo("Backbone listener expired: %s", it->first.ToString().c_str());
            it = mBackboneListeners.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void McastForwarder::ReportCounters(void)
{
    const Counters &c = mThreadToBackbone;

    VerifyOrExit(memcmp(&c, &mReportedThreadToBackbone, sizeof(Counters)) != 0);
    otbrLogInfo("thread->backbone: received %llu forwarded %llu rejected %llu duplicates %llu rate-limited %llu "
                "errors %llu",
                static_cast<unsigned long long>(c.mReceived), static_cast<unsigned long long>(c.mForwarded),
                static_cast<unsigned long long>(c.mRejected), static_cast<unsigned long long>(c.mDuplicates),
                static_cast<unsigned long long>(c.mRateLimited), static_cast<unsigned long long>(c.mErrors));
    mReportedThreadToBackbone = c;

exit:
    return;
}

void McastForwarder::Update(MainloopContext &aMainloop)
{
    VerifyOrExit(mEnabled);

    if (mBackboneTap.IsOpen())
    {
        aMainloop.AddFdToReadSet(mBackboneTap.GetFd());
    }
    if (mThreadTap.IsOpen())
    {
        aMainloop.AddFdToReadSet(mThreadTap.GetFd());
    }

    {
        Timepoint      now         = Clock::now();
        Timepoint      next        = mNextExpire < mNextReport ? mNextExpire : mNextReport;
        uint64_t       remainingMs = now >= next ? 0 : std::chrono::duration_cast<Milliseconds>(next - now).count();
        struct timeval timeout;

        timeout.tv_sec  = static_cast<time_t>(remainingMs / 1000);
        timeout.tv_usec = static_cast<suseconds_t>((remainingMs % 1000) * 1000);
        if (timercmp(&timeout, &aMainloop.mTimeout, <))
        {
            aMainloop.mTimeout = timeout;
        }
    }

exit:
    return;
}

void McastForwarder::Process(const MainloopContext &aMainloop)
{
    VerifyOrExit(mEnabled);

    if (mBackboneTap.IsOpen() && FD_ISSET(mBackboneTap.GetFd(), &aMainloop.mReadFdSet))
    {
        otbrError error =
            mBackboneTap.Read([this](const uint8_t *aFrame, size_t aLength) { HandleMldFrame(aFrame, aLength); });

        if (error != OTBR_ERROR_NONE)
        {
            otbrLogWarning("Reading from %s failed: %s", mBackboneIfName.c_str(), strerror(errno));
        }
    }

    if (mThreadTap.IsOpen() && FD_ISSET(mThreadTap.GetFd(), &aMainloop.mReadFdSet))
    {
        otbrError error =
            mThreadTap.Read([this](const uint8_t *aFrame, size_t aLength) { HandleThreadFrame(aFrame, aLength); });

        if (error != OTBR_ERROR_NONE)
        {
            otbrLogWarning("Reading from %s failed: %s", mThreadIfName.c_str(), strerror(errno));
        }
    }

    if (Clock::now() >= mNextExpire)
    {
        ExpireBackboneListeners();
        mNextExpire = Clock::now() + Seconds(kExpireIntervalSec);
    }
    if (Clock::now() >= mNextReport)
    {
        ReportCounters();
        mNextReport = Clock::now() + Seconds(kReportIntervalSec);
    }

exit:
    return;
}

} // namespace otbr
