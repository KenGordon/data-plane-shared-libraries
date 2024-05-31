#include <iostream>
#include <memory>
#include <utility>
#include <fstream>

#include "absl/log/check.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
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


ABSL_FLAG(std::string, output_path,
          "fetch_auth_token_out",
          "Path to the output of this tool");


int main(int argc, char **argv)
{
    absl::ParseCommandLine(argc, argv);
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

            const auto output_path = absl::GetFlag(FLAGS_output_path);
            // We can improve this by checking the directly of the file exists.
            // Currently it silently fails to write if the dir is not there.
            std::ofstream fout(output_path);
            fout << *context.response->session_token;

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