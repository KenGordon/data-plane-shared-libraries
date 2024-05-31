#include <iostream>
#include <memory>
#include <utility>

#include "absl/log/check.h"
#include "absl/synchronization/notification.h"
#include "src/public/cpio/interface/cpio.h"
#include "src/cpio/client_providers/global_cpio/global_cpio.h"

using google::scp::core::AsyncContext;
using google::scp::cpio::client_providers::GlobalCpio;
using google::scp::cpio::client_providers::GetSessionTokenRequest;
using google::scp::cpio::client_providers::GetSessionTokenResponse;

/*
This tool fetches JWT auth token from IDP (Managed Identity in production) and write it to stdout.
TODO: env vars? parameters?

*/

int main () {
    // Setup
    google::scp::cpio::CpioOptions cpio_options;
    cpio_options.log_option = google::scp::cpio::LogOption::kConsoleLog;
    CHECK(google::scp::cpio::Cpio::InitCpio(cpio_options).Successful())
        << "Failed to initialize CPIO library";
    auto provider = GlobalCpio::GetGlobalCpio().GetAuthTokenProvider();
    CHECK(provider.ok()) << "failed to get auth token provider";
    auto auth_token_provider = *provider;
    // TODO: check if you really need to do this. It might be done by InitCpio for example.
    CHECK(auth_token_provider->Init().Successful())
        << "Failed to initialize auth_token_provider";
    CHECK(auth_token_provider->Run().Successful())
        << "Failed to run auth_token_provider";
    
    // Fetch token
    auto request = std::make_shared<GetSessionTokenRequest>();
    absl::Notification finished;
    AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>
        get_token_context(std::move(request), [&finished](auto& context) {
            CHECK(context.result.Successful()) << "GetSessionTokenRequest failed";
            CHECK(context.response->session_token->size() > 0) << "Session token needs to have length more than zero";
            // TODO: check there is no other stdout log.
            std::cout << *context.response->session_token << std::endl;
            finished.Notify();
        });
    CHECK(auth_token_provider->GetSessionToken(get_token_context).Successful())
     << "Failed to run auth_token_provider";
    finished.WaitForNotification();


    // Tear down
    CHECK(auth_token_provider->Stop().Successful())
        << "Failed to stop auth_token_provider";
    google::scp::cpio::Cpio::ShutdownCpio(cpio_options);
    
    return 0;
}