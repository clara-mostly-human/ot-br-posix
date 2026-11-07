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

#define OTBR_LOG_TAG "FIREWALL"

#include "firewall/pf_firewall.hpp"

#include <algorithm>
#include <ctype.h>
#include <sstream>
#include <string.h>
#include <utility>

#include "common/logging.hpp"

namespace otbr {
namespace Firewall {

const char *const PfFirewall::kAnchorName           = "otbr";
const char *const PfFirewall::kIngressDenySrcTable  = "ingress_deny_src";
const char *const PfFirewall::kIngressAllowDstTable = "ingress_allow_dst";
const char *const PfFirewall::kThreadTag            = "otbr_thread";

PfFirewall::PfFirewall(IPfctl &aPfctl, std::string aThreadInterfaceName)
    : mPfctl(aPfctl)
    , mThreadIfName(std::move(aThreadInterfaceName))
    , mInitialized(false)
    , mIngressFilterEnabled(false)
    , mNat44Enabled(false)
{
}

otbrError PfFirewall::RunPfctl(const std::vector<std::string> &aArgs, const std::string &aInput, std::string &aOutput)
{
    std::string stderrText;
    otbrError   error = mPfctl.Run(aArgs, aInput, aOutput, stderrText);

    if (error != OTBR_ERROR_NONE)
    {
        std::string command = "pfctl";

        for (const std::string &arg : aArgs)
        {
            command += " ";
            command += arg;
        }
        otbrLogWarning("`%s` failed: %s", command.c_str(), stderrText.c_str());
    }

    return error;
}

otbrError PfFirewall::EnablePf(void)
{
    // `pfctl -E` enables pf with a reference count and reports the reference
    // as "Token : <n>", which `pfctl -X` needs to release it again. pf stays
    // enabled while anyone holds a reference, so this neither disturbs nor
    // depends on other users of pf on the host.
    otbrError   error;
    std::string output;
    std::string stderrText;
    std::string all;
    size_t      pos;

    error = mPfctl.Run({"-E"}, "", output, stderrText);
    VerifyOrExit(error == OTBR_ERROR_NONE, otbrLogWarning("`pfctl -E` failed: %s", stderrText.c_str()));

    // pfctl prints the reference as "Token : <n>"; only the digits after the
    // word matter, whichever stream and spacing a given release uses. pf is
    // enabled either way, so a token that cannot be found is not fatal: the
    // reference just cannot be released on Deinit().
    all = output + stderrText;
    mEnableToken.clear();
    pos = all.find("Token");
    if (pos == std::string::npos)
    {
        pos = all.find("token");
    }
    if (pos != std::string::npos)
    {
        while (pos < all.size() && !isdigit(static_cast<unsigned char>(all[pos])) && all[pos] != '\n')
        {
            pos++;
        }
        for (; pos < all.size() && isdigit(static_cast<unsigned char>(all[pos])); pos++)
        {
            mEnableToken += all[pos];
        }
    }
    if (mEnableToken.empty())
    {
        otbrLogWarning("`pfctl -E` did not report a reference token; pf stays enabled on exit: %s", all.c_str());
    }

exit:
    return error;
}

void PfFirewall::DisablePf(void)
{
    std::string output;

    if (!mEnableToken.empty())
    {
        // Failure only means the reference lingers; nothing to do about it.
        RunPfctl({"-X", mEnableToken}, "", output);
        mEnableToken.clear();
    }
}

otbrError PfFirewall::VerifyAnchorReferenced(const char *aListFlag, const char *aDirective)
{
    // A referenced anchor shows up in the main ruleset listing as, for example,
    // `anchor "otbr" all` (`pfctl -s rules`) or `nat-anchor "otbr" all`
    // (`pfctl -s nat`).
    otbrError          error;
    std::string        output;
    std::string        wanted = std::string(aDirective) + " \"" + kAnchorName + "\"";
    std::istringstream lines;
    std::string        line;
    bool               found = false;

    SuccessOrExit(error = RunPfctl({"-s", aListFlag}, "", output));

    lines.str(output);
    while (std::getline(lines, line))
    {
        size_t start = line.find_first_not_of(" \t");

        if (start != std::string::npos && line.compare(start, wanted.size(), wanted) == 0)
        {
            found = true;
            break;
        }
    }
    VerifyOrExit(found, error = OTBR_ERROR_NOT_FOUND);

exit:
    if (error == OTBR_ERROR_NOT_FOUND)
    {
        otbrLogCrit("The main pf ruleset does not reference the OTBR anchor: add `%s` to /etc/pf.conf "
                    "(script/_firewall does this) and reload it with `pfctl -f /etc/pf.conf`",
                    wanted.c_str());
    }
    return error;
}

otbrError PfFirewall::FlushAnchor(void)
{
    std::string output;

    return RunPfctl({"-a", kAnchorName, "-F", "all"}, "", output);
}

otbrError PfFirewall::Init(void)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(!mInitialized, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(!mThreadIfName.empty(), error = OTBR_ERROR_INVALID_ARGS);

    SuccessOrExit(error = EnablePf());
    SuccessOrExit(error = VerifyAnchorReferenced("rules", "anchor"));
    SuccessOrExit(error = FlushAnchor());

    mInitialized = true;

exit:
    if (error != OTBR_ERROR_NONE)
    {
        DisablePf();
    }
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

otbrError PfFirewall::Deinit(void)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mInitialized);

    error = FlushAnchor();
    DisablePf();

    mInitialized          = false;
    mIngressFilterEnabled = false;
    mNat44Enabled         = false;
    mUpstreamIfName.clear();

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

std::string PfFirewall::GenerateRuleset(void) const
{
    // pf insists on section order: options (tables), translation, filtering.
    const std::string &thread   = mThreadIfName;
    const std::string  denySrc  = std::string("<") + kIngressDenySrcTable + ">";
    const std::string  allowDst = std::string("<") + kIngressAllowDstTable + ">";
    std::string        rules;

    rules += "# Installed by otbr-agent; do not edit.\n";
    rules += "table " + denySrc + " persist\n";
    rules += "table " + allowDst + " persist\n";

    if (mNat44Enabled)
    {
        // Masquerade IPv4 that arrived on the Thread interface (the NAT64 egress
        // path) out the upstream interface. A nat rule cannot match the inbound
        // interface, so the packets are tagged on the way in and the nat rule
        // keys on the tag. `nat pass` lets the translated packets through
        // without a matching filter rule (the host's own ruleset may filter
        // outbound on the upstream interface) and keeps state for the replies.
        rules += "nat pass on " + mUpstreamIfName + " inet tagged " + kThreadTag + " -> (" + mUpstreamIfName + ")\n";
        rules += "pass in quick on " + thread + " inet tag " + kThreadTag + "\n";
    }

    if (mIngressFilterEnabled)
    {
        // The ip6tables FORWARD ingress chain, with one difference: pf also sees
        // the host's own output on the Thread interface, so that is exempted
        // first. `(<thread>)` tracks the interface's addresses as they change
        // (the OMR address only arrives after the ruleset is loaded); `(self)`
        // covers the host's other addresses as of load time.
        rules += "pass out quick on " + thread + " inet6 from (" + thread + ") to any\n";
        rules += "pass out quick on " + thread + " inet6 from (self) to any\n";
        // Spoof protection: transit packets claiming an on-mesh source.
        rules += "block out quick on " + thread + " inet6 from " + denySrc + " to any\n";
        // Advertised on-mesh destinations are reachable by design.
        rules += "pass out quick on " + thread + " inet6 from any to " + allowDst + "\n";
        // Multicast toward the mesh stays allowed; anything else is unsolicited.
        rules += "pass out quick on " + thread + " inet6 from any to ff00::/8\n";
        rules += "block out quick on " + thread + " inet6 all\n";
    }

    return rules;
}

otbrError PfFirewall::LoadRuleset(void)
{
    std::string output;

    return RunPfctl({"-a", kAnchorName, "-f", "-"}, GenerateRuleset(), output);
}

otbrError PfFirewall::EnableIngressFilter(void)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mInitialized, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(!mIngressFilterEnabled);

    mIngressFilterEnabled = true;
    error                 = LoadRuleset();
    if (error != OTBR_ERROR_NONE)
    {
        mIngressFilterEnabled = false;
    }

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

otbrError PfFirewall::EnableNat44Masquerade(const std::string &aUpstreamInterfaceName)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mInitialized, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(!aUpstreamInterfaceName.empty(), error = OTBR_ERROR_INVALID_ARGS);
    VerifyOrExit(!mNat44Enabled);

    SuccessOrExit(error = VerifyAnchorReferenced("nat", "nat-anchor"));

    mUpstreamIfName = aUpstreamInterfaceName;
    mNat44Enabled   = true;
    error           = LoadRuleset();
    if (error != OTBR_ERROR_NONE)
    {
        mNat44Enabled = false;
        mUpstreamIfName.clear();
    }

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

otbrError PfFirewall::DisableNat44Masquerade(void)
{
    otbrError   error = OTBR_ERROR_NONE;
    std::string upstream;

    VerifyOrExit(mInitialized, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(mNat44Enabled);

    upstream.swap(mUpstreamIfName);
    mNat44Enabled = false;
    error         = LoadRuleset();
    if (error != OTBR_ERROR_NONE)
    {
        mNat44Enabled = true;
        mUpstreamIfName.swap(upstream);
    }

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

otbrError PfFirewall::ReplaceTable(const char *aTable, const std::vector<Ip6Prefix> &aPrefixes)
{
    std::vector<std::string> args = {"-a", kAnchorName, "-t", aTable, "-T"};
    std::vector<std::string> addresses;
    std::string              output;

    for (const Ip6Prefix &prefix : aPrefixes)
    {
        addresses.push_back(prefix.ToString());
    }
    // A stable order keeps the pfctl invocation reproducible; duplicates would
    // only make pfctl complain.
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());

    if (addresses.empty())
    {
        args.push_back("flush");
    }
    else
    {
        args.push_back("replace");
        args.insert(args.end(), addresses.begin(), addresses.end());
    }

    return RunPfctl(args, "", output);
}

otbrError PfFirewall::ReplaceIngressPrefixes(const std::vector<Ip6Prefix> &aDenySrc,
                                             const std::vector<Ip6Prefix> &aAllowDst)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mIngressFilterEnabled, error = OTBR_ERROR_INVALID_STATE);

    mDenySrc  = aDenySrc;
    mAllowDst = aAllowDst;

    error = ReplaceTable(kIngressDenySrcTable, aDenySrc);
    if (error == OTBR_ERROR_NONE)
    {
        error = ReplaceTable(kIngressAllowDstTable, aAllowDst);
    }
    if (error != OTBR_ERROR_NONE)
    {
        // A table pfctl cannot find means the anchor was emptied behind the
        // agent's back (the nftables backend sees ENOENT then): put everything
        // back, the tables' new contents included.
        otbrLogWarning("PfFirewall: replacing a table failed; reinstalling the anchor");
        error = Reinstall();
    }

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

otbrError PfFirewall::AnchorLists(const char *aListFlag, const std::string &aNeedle, bool &aFound)
{
    otbrError   error;
    std::string output;

    aFound = false;
    SuccessOrExit(error = RunPfctl({"-a", kAnchorName, "-s", aListFlag}, "", output));
    aFound = output.find(aNeedle) != std::string::npos;

exit:
    return error;
}

otbrError PfFirewall::VerifyInstalled(bool &aReinstalled)
{
    otbrError error = OTBR_ERROR_NONE;
    bool      found = true;

    aReinstalled = false;
    VerifyOrExit(mInitialized, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(mIngressFilterEnabled || mNat44Enabled);

    // pfctl prints the rules in its own words, so the needles are the parts
    // every rule of ours shares: the interface for the filter, the table names,
    // the upstream interface for the NAT rule.
    if (mIngressFilterEnabled)
    {
        SuccessOrExit(error = AnchorLists("rules", "quick on " + mThreadIfName + " inet6", found));
        VerifyOrExit(found);
        SuccessOrExit(error = AnchorLists("Tables", kIngressDenySrcTable, found));
        VerifyOrExit(found);
        SuccessOrExit(error = AnchorLists("Tables", kIngressAllowDstTable, found));
        VerifyOrExit(found);
    }
    if (mNat44Enabled)
    {
        SuccessOrExit(error = AnchorLists("nat", "nat pass on " + mUpstreamIfName + " inet", found));
        VerifyOrExit(found);
    }

exit:
    if (error != OTBR_ERROR_NONE && error != OTBR_ERROR_INVALID_STATE)
    {
        otbrLogWarning("PfFirewall: could not list the anchor: %s", otbrErrorString(error));
        error = OTBR_ERROR_NONE;
    }
    else if (!found)
    {
        otbrLogWarning("PfFirewall: the anchor \"%s\" lost its rules behind the agent's back; reinstalling",
                       kAnchorName);
        error        = Reinstall();
        aReinstalled = (error == OTBR_ERROR_NONE);
    }
    return error;
}

otbrError PfFirewall::Reinstall(void)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mInitialized, error = OTBR_ERROR_INVALID_STATE);

    SuccessOrExit(error = FlushAnchor());
    SuccessOrExit(error = LoadRuleset());
    if (mIngressFilterEnabled)
    {
        SuccessOrExit(error = ReplaceTable(kIngressDenySrcTable, mDenySrc));
        SuccessOrExit(error = ReplaceTable(kIngressAllowDstTable, mAllowDst));
    }

exit:
    otbrLogResult(error, "PfFirewall: %s", __FUNCTION__);
    return error;
}

} // namespace Firewall
} // namespace otbr
