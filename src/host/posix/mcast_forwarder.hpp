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

/**
 * @file
 *   This file includes definitions for the userspace Backbone Router
 *   multicast forwarder.
 */

#ifndef OTBR_HOST_POSIX_MCAST_FORWARDER_HPP_
#define OTBR_HOST_POSIX_MCAST_FORWARDER_HPP_

#include "openthread-br/config.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include <openthread/backbone_router_ftd.h>

#include "common/code_utils.hpp"
#include "common/mainloop.hpp"
#include "common/time.hpp"
#include "common/types.hpp"
#include "host/posix/bpf_tap.hpp"

namespace otbr {

/**
 * Userspace multicast forwarder for a Backbone Router.
 *
 * The OpenThread posix platform forwards multicast between the Thread
 * network and the backbone through the kernel's multicast routing (MRT6),
 * which only Linux offers. This class takes that role on platforms without
 * it. It tracks the groups that have listeners on each side — the Thread
 * side from the core's Multicast Listener Registration table, the backbone
 * side by snooping MLD reports on the backbone interface — and moves
 * packets between the Thread interface and the backbone through BPF taps.
 *
 * Only the listener tracking is implemented so far; no packet is forwarded.
 */
class McastForwarder : public MainloopProcessor, private NonCopyable
{
public:
    /**
     * A group membership change carried by an MLD message.
     */
    struct MldRecord
    {
        Ip6Address mGroup;
        bool       mIsJoin;
    };

    /**
     * Constructor.
     *
     * @param[in] aThreadIfName    The Thread network interface name.
     * @param[in] aBackboneIfName  The backbone interface name; may be empty.
     */
    McastForwarder(const std::string &aThreadIfName, const std::string &aBackboneIfName);

    ~McastForwarder(void) override;

    /**
     * Handles a Backbone Router state change. Forwarding runs only while this
     * device is the Primary Backbone Router.
     */
    void HandleBackboneRouterStateChange(otBackboneRouterState aState);

    /**
     * Handles a change of the core's Multicast Listener Registration table.
     */
    void HandleBackboneMulticastListenerEvent(otBackboneRouterMulticastListenerEvent aEvent,
                                              const Ip6Address                      &aAddress);

    bool IsEnabled(void) const { return mEnabled; }
    bool HasThreadListener(const Ip6Address &aGroup) const { return mThreadListeners.count(aGroup) != 0; }
    bool HasBackboneListener(const Ip6Address &aGroup) const { return mBackboneListeners.count(aGroup) != 0; }

    /**
     * Extracts the group membership changes an MLD message carries.
     *
     * @param[in]  aPacket   An IPv6 packet, starting at the IPv6 header.
     * @param[in]  aLength   The packet length.
     * @param[out] aRecords  The membership changes, in message order.
     *
     * @returns true if the packet is a well-formed MLD report or done message, false otherwise.
     */
    static bool ParseMld(const uint8_t *aPacket, size_t aLength, std::vector<MldRecord> &aRecords);

    /**
     * Applies the membership changes of one MLD message to the backbone
     * listener table. Groups the forwarder does not track are ignored.
     */
    void HandleMldRecords(const std::vector<MldRecord> &aRecords);

    /**
     * Indicates whether a group is one the forwarder tracks: multicast with a
     * scope beyond link-local, the only scopes a Backbone Router carries.
     */
    static bool IsTrackedGroup(const Ip6Address &aGroup);

    void Update(MainloopContext &aMainloop) override;
    void Process(const MainloopContext &aMainloop) override;

private:
    // RFC 3810 §9.4: Multicast Listener Interval = Robustness Variable (2) *
    // Query Interval (125 s) + Query Response Interval (10 s).
    static constexpr uint32_t kBackboneListenerTimeoutSec = 260;
    static constexpr uint32_t kExpireIntervalSec          = 30;

    void Enable(void);
    void Disable(void);
    void HandleMldFrame(const uint8_t *aFrame, size_t aLength);
    void ExpireBackboneListeners(void);

    std::string                     mThreadIfName;
    std::string                     mBackboneIfName;
    bool                            mEnabled;
    BpfTap                          mMldTap;
    std::set<Ip6Address>            mThreadListeners;
    std::map<Ip6Address, Timepoint> mBackboneListeners;
    Timepoint                       mNextExpire;
};

} // namespace otbr

#endif // OTBR_HOST_POSIX_MCAST_FORWARDER_HPP_
