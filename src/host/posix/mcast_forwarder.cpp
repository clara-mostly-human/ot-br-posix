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

#include <net/bpf.h>
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

} // namespace

// Odr-used (chrono takes them by reference); C++11 needs the definitions.
constexpr uint32_t McastForwarder::kBackboneListenerTimeoutSec;
constexpr uint32_t McastForwarder::kExpireIntervalSec;

McastForwarder::McastForwarder(const std::string &aThreadIfName, const std::string &aBackboneIfName)
    : mThreadIfName(aThreadIfName)
    , mBackboneIfName(aBackboneIfName)
    , mEnabled(false)
    , mNextExpire(Clock::now())
{
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
    otbrError error;

    VerifyOrExit(!mEnabled);
    mEnabled = true;
    otbrLogNotice("Enabled: thread %s, backbone %s (listener tracking only, no forwarding yet)", mThreadIfName.c_str(),
                  mBackboneIfName.empty() ? "(none)" : mBackboneIfName.c_str());

    VerifyOrExit(!mBackboneIfName.empty(), otbrLogWarning("No backbone interface; backbone listeners unknown"));

    // The host itself may be a listener, so its own MLD reports count too.
    error = mMldTap.Open(mBackboneIfName, /* aSeeSent */ true);
    VerifyOrExit(error == OTBR_ERROR_NONE, otbrLogWarning("Cannot snoop MLD on %s", mBackboneIfName.c_str()));

    switch (mMldTap.GetDataLinkType())
    {
    case DLT_NULL:
        error = mMldTap.SetFilter(kIcmp6FilterNull, sizeof(kIcmp6FilterNull) / sizeof(kIcmp6FilterNull[0]));
        break;
    default:
        error = mMldTap.SetFilter(kIcmp6FilterEthernet, sizeof(kIcmp6FilterEthernet) / sizeof(kIcmp6FilterEthernet[0]));
        break;
    }
    if (error != OTBR_ERROR_NONE)
    {
        otbrLogWarning("Cannot install the MLD filter on %s: %s", mBackboneIfName.c_str(), strerror(errno));
        mMldTap.Close();
    }

exit:
    return;
}

void McastForwarder::Disable(void)
{
    VerifyOrExit(mEnabled);
    mEnabled = false;
    mMldTap.Close();
    mBackboneListeners.clear();
    otbrLogNotice("Disabled");

exit:
    return;
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
    size_t                 linkHeader = mMldTap.GetLinkHeaderLength();
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

void McastForwarder::Update(MainloopContext &aMainloop)
{
    VerifyOrExit(mEnabled);

    if (mMldTap.IsOpen())
    {
        aMainloop.AddFdToReadSet(mMldTap.GetFd());
    }

    {
        Timepoint now = Clock::now();
        uint64_t  remainingMs =
            now >= mNextExpire ? 0 : std::chrono::duration_cast<Milliseconds>(mNextExpire - now).count();
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

    if (mMldTap.IsOpen() && FD_ISSET(mMldTap.GetFd(), &aMainloop.mReadFdSet))
    {
        otbrError error =
            mMldTap.Read([this](const uint8_t *aFrame, size_t aLength) { HandleMldFrame(aFrame, aLength); });

        if (error != OTBR_ERROR_NONE)
        {
            otbrLogWarning("Reading MLD from %s failed: %s", mBackboneIfName.c_str(), strerror(errno));
        }
    }

    if (Clock::now() >= mNextExpire)
    {
        ExpireBackboneListeners();
        mNextExpire = Clock::now() + Seconds(kExpireIntervalSec);
    }

exit:
    return;
}

} // namespace otbr
