/*
 *    Copyright (c) 2023, The OpenThread Authors.
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

#include <gtest/gtest.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#ifdef __APPLE__
#include <dns_sd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include <set>
#include <vector>

#include "common/mainloop.hpp"
#include "common/mainloop_manager.hpp"
#include "mdns/mdns.hpp"

using namespace otbr;
using namespace otbr::Mdns;

static constexpr int kTimeoutSeconds = 3;

int RunMainloopUntilTimeout(int aSeconds)
{
    using namespace otbr;

    int  rval      = 0;
    auto beginTime = Clock::now();

    while (true)
    {
        MainloopContext mainloop;

        mainloop.mMaxFd   = -1;
        mainloop.mTimeout = {1, 0};
        FD_ZERO(&mainloop.mReadFdSet);
        FD_ZERO(&mainloop.mWriteFdSet);
        FD_ZERO(&mainloop.mErrorFdSet);

        MainloopManager::GetInstance().Update(mainloop);
        rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                      (mainloop.mTimeout.tv_sec == INT_MAX ? nullptr : &mainloop.mTimeout));

        if (rval < 0)
        {
            perror("select");
            break;
        }

        MainloopManager::GetInstance().Process(mainloop);

        if (Clock::now() - beginTime >= std::chrono::seconds(aSeconds))
        {
            break;
        }
    }

    return rval;
}

template <typename Container> std::set<typename Container::value_type> AsSet(const Container &aContainer)
{
    return std::set<typename Container::value_type>(aContainer.begin(), aContainer.end());
}

Publisher::ResultCallback NoOpCallback(void)
{
    return [](otbrError aError) { OTBR_UNUSED_VARIABLE(aError); };
}

std::map<std::string, std::vector<uint8_t>> AsTxtMap(const Publisher::TxtData &aTxtData)
{
    Publisher::TxtList                          txtList;
    std::map<std::string, std::vector<uint8_t>> map;

    Publisher::DecodeTxtData(txtList, aTxtData.data(), aTxtData.size());
    for (const auto &entry : txtList)
    {
        map[entry.mKey] = entry.mValue;
    }

    return map;
}

Publisher::TxtList sTxtList1{{"a", "1"}, {"b", "2"}};
Publisher::TxtData sTxtData1;
Ip6Address         sAddr1;
Ip6Address         sAddr2;
Ip6Address         sAddr3;
Ip6Address         sAddr4;

class MdnsTest : public ::testing::Test
{
protected:
    MdnsTest()
    {
        SuccessOrDie(Ip6Address::FromString("2002::1", sAddr1), "");
        SuccessOrDie(Ip6Address::FromString("2002::2", sAddr2), "");
        SuccessOrDie(Ip6Address::FromString("2002::3", sAddr3), "");
        SuccessOrDie(Ip6Address::FromString("2002::4", sAddr4), "");
        SuccessOrDie(Publisher::EncodeTxtData(sTxtList1, sTxtData1), "");
    }
};

std::unique_ptr<Publisher> CreatePublisher(void)
{
    bool                       ready = false;
    std::unique_ptr<Publisher> publisher{Publisher::Create([&ready](Mdns::Publisher::State aState) {
        if (aState == Publisher::State::kReady)
        {
            ready = true;
        }
    })};

    publisher->Start();
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_TRUE(ready);

    return publisher;
}

#ifdef __APPLE__
bool IsLoopbackNetif(uint32_t aNetifIndex)
{
    bool            isLoopback = false;
    struct ifaddrs *ifAddrs    = nullptr;

    if (getifaddrs(&ifAddrs) != 0)
    {
        ifAddrs = nullptr;
    }

    for (const struct ifaddrs *ifAddr = ifAddrs; ifAddr != nullptr; ifAddr = ifAddr->ifa_next)
    {
        if (if_nametoindex(ifAddr->ifa_name) == aNetifIndex)
        {
            isLoopback = (ifAddr->ifa_flags & IFF_LOOPBACK) != 0;
            break;
        }
    }

    if (ifAddrs != nullptr)
    {
        freeifaddrs(ifAddrs);
    }

    return isLoopback;
}
#endif

// On Apple platforms, mDNSResponder reports what this host publishes on the loopback interface in addition to the
// interfaces it can be reached through. Subscribers must be notified for the latter only. There is nothing to check
// on other platforms, where mDNSResponder uses the loopback interface only as a fallback.
void ExpectNotOnLoopback(uint32_t aNetifIndex)
{
#ifdef __APPLE__
    EXPECT_FALSE(IsLoopbackNetif(aNetifIndex)) << "notified on the loopback interface " << aNetifIndex;
#else
    OTBR_UNUSED_VARIABLE(aNetifIndex);
#endif
}

void CheckServiceInstance(const Publisher::DiscoveredInstanceInfo aInstanceInfo,
                          bool                                    aRemoved,
                          const std::string                      &aHostName,
                          const std::vector<Ip6Address>          &aAddresses,
                          const std::string                      &aServiceName,
                          uint16_t                                aPort,
                          const Publisher::TxtData                aTxtData)
{
    EXPECT_EQ(aRemoved, aInstanceInfo.mRemoved);
    EXPECT_EQ(aServiceName, aInstanceInfo.mName);
    if (!aRemoved)
    {
        EXPECT_EQ(aHostName, aInstanceInfo.mHostName);
        EXPECT_EQ(AsSet(aAddresses), AsSet(aInstanceInfo.mAddresses));
        EXPECT_EQ(aPort, aInstanceInfo.mPort);
        EXPECT_TRUE(AsTxtMap(aTxtData) == AsTxtMap(aInstanceInfo.mTxtData));
    }
}

void CheckServiceInstanceAdded(const Publisher::DiscoveredInstanceInfo aInstanceInfo,
                               const std::string                      &aHostName,
                               const std::vector<Ip6Address>          &aAddresses,
                               const std::string                      &aServiceName,
                               uint16_t                                aPort,
                               const Publisher::TxtData                aTxtData)
{
    CheckServiceInstance(aInstanceInfo, false, aHostName, aAddresses, aServiceName, aPort, aTxtData);
}

void CheckServiceInstanceRemoved(const Publisher::DiscoveredInstanceInfo aInstanceInfo, const std::string &aServiceName)
{
    CheckServiceInstance(aInstanceInfo, true, "", {}, aServiceName, 0, {});
}

void CheckHostAdded(const Publisher::DiscoveredHostInfo &aHostInfo,
                    const std::string                   &aHostName,
                    const std::vector<Ip6Address>       &aAddresses)
{
    EXPECT_EQ(aHostName, aHostInfo.mHostName);
    EXPECT_EQ(AsSet(aAddresses), AsSet(aHostInfo.mAddresses));
}

TEST_F(MdnsTest, SubscribeHost)
{
    std::unique_ptr<Publisher>    pub = CreatePublisher();
    std::string                   lastHostName;
    Publisher::DiscoveredHostInfo lastHostInfo{};

    auto clearLastHost = [&lastHostName, &lastHostInfo] {
        lastHostName = "";
        lastHostInfo = {};
    };

    pub->AddSubscriptionCallbacks(
        nullptr,
        [&lastHostName, &lastHostInfo](const std::string &aHostName, const Publisher::DiscoveredHostInfo &aHostInfo) {
            ExpectNotOnLoopback(aHostInfo.mNetifIndex);
            lastHostName = aHostName;
            lastHostInfo = aHostInfo;
        });
    pub->SubscribeHost("host1");

    pub->PublishHost("host1", Publisher::AddressList{sAddr1, sAddr2}, NoOpCallback());
    pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                        NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("host1", lastHostName);
    CheckHostAdded(lastHostInfo, "host1.local.", {sAddr1, sAddr2});
    clearLastHost();

    pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("", lastHostName);
    clearLastHost();

    pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
    pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("", lastHostName);
    clearLastHost();
}

TEST_F(MdnsTest, SubscribeServiceInstance)
{
    std::unique_ptr<Publisher>        pub = CreatePublisher();
    std::string                       lastServiceType;
    Publisher::DiscoveredInstanceInfo lastInstanceInfo{};

    auto clearLastInstance = [&lastServiceType, &lastInstanceInfo] {
        lastServiceType  = "";
        lastInstanceInfo = {};
    };

    pub->AddSubscriptionCallbacks(
        [&lastServiceType, &lastInstanceInfo](const std::string                &aType,
                                              Publisher::DiscoveredInstanceInfo aInstanceInfo) {
            ExpectNotOnLoopback(aInstanceInfo.mNetifIndex);
            lastServiceType  = aType;
            lastInstanceInfo = aInstanceInfo;
        },
        nullptr);
    pub->SubscribeService("_test._tcp", "service1");

    pub->PublishHost("host1", Publisher::AddressList{sAddr1, sAddr2}, NoOpCallback());
    pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                        NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service1", 11111, sTxtData1);
    clearLastInstance();

    pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("", lastServiceType);
    clearLastInstance();

    pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
    pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("", lastServiceType);
    clearLastInstance();
}

TEST_F(MdnsTest, SubscribeServiceType)
{
    std::unique_ptr<Publisher>        pub = CreatePublisher();
    std::string                       lastServiceType;
    Publisher::DiscoveredInstanceInfo lastInstanceInfo{};

    auto clearLastInstance = [&lastServiceType, &lastInstanceInfo] {
        lastServiceType  = "";
        lastInstanceInfo = {};
    };

    pub->AddSubscriptionCallbacks(
        [&lastServiceType, &lastInstanceInfo](const std::string                &aType,
                                              Publisher::DiscoveredInstanceInfo aInstanceInfo) {
            ExpectNotOnLoopback(aInstanceInfo.mNetifIndex);
            lastServiceType  = aType;
            lastInstanceInfo = aInstanceInfo;
        },
        nullptr);
    pub->SubscribeService("_test._tcp", "");

    pub->PublishHost("host1", Publisher::AddressList{sAddr1, sAddr2}, NoOpCallback());
    pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                        NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service1", 11111, sTxtData1);
    clearLastInstance();

    pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service2", 22222, {});
    clearLastInstance();

    pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
    pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr3}, "service3", 33333, {});
    clearLastInstance();

    pub->UnpublishHost("host2", NoOpCallback());
    pub->UnpublishService("service3", "_test._tcp", NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceRemoved(lastInstanceInfo, "service3");
    clearLastInstance();

    pub->PublishHost("host2", {sAddr3}, NoOpCallback());
    pub->PublishService("host2", "service3", "_test._tcp", {}, 44444, {}, NoOpCallback());
    pub->PublishHost("host2", {sAddr3, sAddr4}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr3, sAddr4}, "service3", 44444, {});
    clearLastInstance();

    pub->PublishHost("host2", {sAddr4}, NoOpCallback());
    RunMainloopUntilTimeout(kTimeoutSeconds);
    EXPECT_EQ("_test._tcp", lastServiceType);
    CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr4}, "service3", 44444, {});
    clearLastInstance();
}

#ifdef __APPLE__
const char kDomainLocal[] = "local.";

void HandleRecordRegistered(DNSServiceRef       aServiceRef,
                            DNSRecordRef        aRecordRef,
                            DNSServiceFlags     aFlags,
                            DNSServiceErrorType aError,
                            void               *aContext)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);
    OTBR_UNUSED_VARIABLE(aRecordRef);
    OTBR_UNUSED_VARIABLE(aFlags);

    EXPECT_EQ(kDNSServiceErr_NoError, aError);
    ++*static_cast<int *>(aContext);
}

void RegisterAddress(DNSServiceRef aConnection,
                     uint32_t      aNetifIndex,
                     const char   *aFullHostName,
                     const char   *aAddress,
                     int          &aRegistered)
{
    Ip6Address   address(aAddress);
    DNSRecordRef record;

    EXPECT_EQ(kDNSServiceErr_NoError,
              DNSServiceRegisterRecord(aConnection, &record, kDNSServiceFlagsShared, aNetifIndex, aFullHostName,
                                       kDNSServiceType_AAAA, kDNSServiceClass_IN, sizeof(address.m8), address.m8,
                                       /* ttl */ 0, HandleRecordRegistered, &aRegistered));
}

void ProcessResultsUntil(DNSServiceRef aConnection, const int &aCount, int aExpectedCount)
{
    int  fd        = DNSServiceRefSockFD(aConnection);
    auto beginTime = Clock::now();

    while (aCount < aExpectedCount && Clock::now() - beginTime < std::chrono::seconds(kTimeoutSeconds))
    {
        fd_set         readFdSet;
        struct timeval timeout = {1, 0};

        FD_ZERO(&readFdSet);
        FD_SET(fd, &readFdSet);

        if (select(fd + 1, &readFdSet, nullptr, nullptr, &timeout) > 0)
        {
            EXPECT_EQ(kDNSServiceErr_NoError, DNSServiceProcessResult(aConnection));
        }
    }
}

void HandleServiceRegistered(DNSServiceRef       aServiceRef,
                             DNSServiceFlags     aFlags,
                             DNSServiceErrorType aError,
                             const char         *aName,
                             const char         *aType,
                             const char         *aDomain,
                             void               *aContext)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);
    OTBR_UNUSED_VARIABLE(aFlags);
    OTBR_UNUSED_VARIABLE(aName);
    OTBR_UNUSED_VARIABLE(aType);
    OTBR_UNUSED_VARIABLE(aDomain);

    EXPECT_EQ(kDNSServiceErr_NoError, aError);
    ++*static_cast<int *>(aContext);
}

// Registers a service on the loopback interface only and expects a subscriber to get no notification for it: nothing
// beyond this host can reach it.
TEST_F(MdnsTest, SubscribeServiceInstanceOnLoopbackOnly)
{
    static const char kInstanceName[] = "otbr-test-loopback-only";
    static const char kType[]         = "_test._tcp";

    uint32_t      loopbackNetifIndex = if_nametoindex("lo0");
    DNSServiceRef registration       = nullptr;
    int           registered         = 0;
    int           notified           = 0;

    ASSERT_NE(0u, loopbackNetifIndex);

    std::unique_ptr<Publisher> pub = CreatePublisher();

    ASSERT_EQ(kDNSServiceErr_NoError,
              DNSServiceRegister(&registration, /* flags */ 0, loopbackNetifIndex, kInstanceName, kType, kDomainLocal,
                                 /* host */ nullptr, htons(55555), /* txtLen */ 0, /* txtRecord */ nullptr,
                                 HandleServiceRegistered, &registered));
    ProcessResultsUntil(registration, registered, 1);
    EXPECT_EQ(1, registered);

    pub->AddSubscriptionCallbacks(
        [&notified](const std::string &aType, Publisher::DiscoveredInstanceInfo aInstanceInfo) {
            OTBR_UNUSED_VARIABLE(aType);
            OTBR_UNUSED_VARIABLE(aInstanceInfo);
            notified++;
        },
        nullptr);
    pub->SubscribeService(kType, kInstanceName);
    RunMainloopUntilTimeout(kTimeoutSeconds);

    EXPECT_EQ(0, notified);

    DNSServiceRefDeallocate(registration);
}

// Registers a host with one address on the loopback interface only and one on every interface, and expects a
// subscriber to get the second one only, from an interface other than the loopback one.
TEST_F(MdnsTest, SubscribeHostIgnoresLoopbackAddresses)
{
    static const char kHostName[]     = "otbr-test-loopback";
    static const char kFullHostName[] = "otbr-test-loopback.local.";

    uint32_t                      loopbackNetifIndex = if_nametoindex("lo0");
    DNSServiceRef                 connection         = nullptr;
    int                           registered         = 0;
    int                           notified           = 0;
    Publisher::DiscoveredHostInfo lastHostInfo{};

    ASSERT_NE(0u, loopbackNetifIndex);

    std::unique_ptr<Publisher> pub = CreatePublisher();

    ASSERT_EQ(kDNSServiceErr_NoError, DNSServiceCreateConnection(&connection));
    RegisterAddress(connection, loopbackNetifIndex, kFullHostName, "fe80::1", registered);
    RegisterAddress(connection, kDNSServiceInterfaceIndexAny, kFullHostName, "2002::5", registered);
    ProcessResultsUntil(connection, registered, 2);
    EXPECT_EQ(2, registered);

    pub->AddSubscriptionCallbacks(nullptr, [&notified, &lastHostInfo](const std::string                   &aHostName,
                                                                      const Publisher::DiscoveredHostInfo &aHostInfo) {
        EXPECT_EQ(kHostName, aHostName);
        ExpectNotOnLoopback(aHostInfo.mNetifIndex);
        notified++;
        lastHostInfo = aHostInfo;
    });
    pub->SubscribeHost(kHostName);
    RunMainloopUntilTimeout(kTimeoutSeconds);

    EXPECT_GE(notified, 1);
    CheckHostAdded(lastHostInfo, kFullHostName, {Ip6Address("2002::5")});

    DNSServiceRefDeallocate(connection);
}
#endif // __APPLE__
