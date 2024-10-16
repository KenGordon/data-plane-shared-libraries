/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "core/curl_client/src/http1_curl_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/log/check.h"
#include "absl/synchronization/notification.h"
#include "core/async_executor/src/async_executor.h"
#include "core/curl_client/src/error_codes.h"
#include "core/curl_client/src/http1_curl_wrapper.h"
#include "public/core/test/interface/execution_result_matchers.h"

using testing::AtLeast;
using testing::ExplainMatchResult;
using testing::InSequence;
using testing::IsSupersetOf;
using testing::NiceMock;
using testing::Not;
using testing::Pair;
using testing::Pointee;
using testing::Return;

namespace google::scp::core::test {
namespace {

class MockCurlWrapperProvider : public NiceMock<Http1CurlWrapperProvider> {
 public:
  MOCK_METHOD(ExecutionResultOr<std::shared_ptr<Http1CurlWrapper>>, MakeWrapper,
              (), (override));
};

class MockCurlWrapper : public NiceMock<Http1CurlWrapper> {
 public:
  ExecutionResultOr<HttpResponse> PerformRequest(
      const HttpRequest& request, const absl::Duration& timeout) noexcept {
    return PerformRequest(request);
  }

  MOCK_METHOD(ExecutionResultOr<HttpResponse>, PerformRequest,
              (const HttpRequest&));
};

class Http1CurlClientTest : public ::testing::Test {
 protected:
  Http1CurlClientTest()
      : cpu_async_executor_(std::make_shared<AsyncExecutor>(/*thread_count=*/4,
                                                            /*queue_cap=*/10)),
        io_async_executor_(std::make_shared<AsyncExecutor>(/*thread_count=*/4,
                                                           /*queue_cap=*/10)),
        wrapper_(std::make_shared<MockCurlWrapper>()),
        provider_(std::make_shared<MockCurlWrapperProvider>()),
        subject_(cpu_async_executor_, io_async_executor_, provider_,
                 common::RetryStrategyOptions(
                     common::RetryStrategyType::Exponential,
                     /*time_duration_ms=*/1UL, /*total_retries=*/10)) {
    CHECK(cpu_async_executor_->Init().Successful())
        << "cpu_async_executor_ initialization unsuccessful";
    CHECK(io_async_executor_->Init().Successful())
        << "io_async_executor_ initialization unsuccessful";
    CHECK(cpu_async_executor_->Run().Successful())
        << "cpu_async_executor_ run unsuccessful";
    CHECK(io_async_executor_->Run().Successful())
        << "io_async_executor_ run unsuccessful";
    ON_CALL(*provider_, MakeWrapper).WillByDefault(Return(wrapper_));
  }

  ~Http1CurlClientTest() {
    CHECK(io_async_executor_->Stop().Successful())
        << "io_async_executor_ stop unsuccessful";
    CHECK(cpu_async_executor_->Stop().Successful())
        << "cpu_async_executor_ stop unsuccessful";
  }

  std::shared_ptr<AsyncExecutorInterface> cpu_async_executor_,
      io_async_executor_;

  std::shared_ptr<MockCurlWrapper> wrapper_;
  std::shared_ptr<MockCurlWrapperProvider> provider_;

  Http1CurlClient subject_;
};

// We only compare the body but we can add more checks if we want.
MATCHER_P(RequestEquals, expected, "") {
  return ExplainMatchResult(arg.body.ToString(), expected.body.ToString(),
                            result_listener);
}

// We only compare the body but we can add more checks if we want.
MATCHER_P(ResponseEquals, expected, "") {
  return ExplainMatchResult(arg.body.ToString(), expected.body.ToString(),
                            result_listener);
}

TEST_F(Http1CurlClientTest, IssuesPerformRequestOnWrapper) {
  AsyncContext<HttpRequest, HttpResponse> http_context;
  http_context.request = std::make_shared<HttpRequest>();
  http_context.request->body = BytesBuffer("buf");

  HttpRequest expected_request;
  expected_request.body = BytesBuffer("buf");
  HttpResponse response;
  response.body = BytesBuffer("resp");
  EXPECT_CALL(*wrapper_, PerformRequest(RequestEquals(expected_request)))
      .WillOnce(Return(response));

  absl::Notification finished;
  http_context.callback = [&response, &finished](auto& http_context) {
    ASSERT_SUCCESS(http_context.result);
    EXPECT_THAT(http_context.response, Pointee(ResponseEquals(response)));
    finished.Notify();
  };

  ASSERT_THAT(subject_.PerformRequest(http_context), IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(Http1CurlClientTest, RetriesWork) {
  AsyncContext<HttpRequest, HttpResponse> http_context;
  http_context.request = std::make_shared<HttpRequest>();
  http_context.request->body = BytesBuffer("buf");

  HttpRequest expected_request;
  expected_request.body = BytesBuffer("buf");
  HttpResponse response;
  response.body = BytesBuffer("resp");

  // Fail 3 times, then succeed.
  {
    InSequence seq;
    EXPECT_CALL(*wrapper_, PerformRequest)
        .Times(3)
        .WillRepeatedly(Return(
            RetryExecutionResult(errors::SC_CURL_CLIENT_REQUEST_FAILED)));
    EXPECT_CALL(*wrapper_, PerformRequest(RequestEquals(expected_request)))
        .WillOnce(Return(response));
  }

  absl::Notification finished;
  http_context.callback = [&response, &finished](auto& http_context) {
    ASSERT_SUCCESS(http_context.result);
    EXPECT_THAT(http_context.response, Pointee(ResponseEquals(response)));
    finished.Notify();
  };

  ASSERT_THAT(subject_.PerformRequest(http_context), IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(Http1CurlClientTest, FailureEnds) {
  AsyncContext<HttpRequest, HttpResponse> http_context;
  http_context.request = std::make_shared<HttpRequest>();
  http_context.request->body = BytesBuffer("buf");

  HttpRequest expected_request;
  expected_request.body = BytesBuffer("buf");
  HttpResponse response;
  response.body = BytesBuffer("resp");

  EXPECT_CALL(*wrapper_, PerformRequest)
      .Times(AtLeast(2))
      .WillRepeatedly(
          Return(RetryExecutionResult(errors::SC_CURL_CLIENT_REQUEST_FAILED)));

  absl::Notification finished;
  http_context.callback = [&finished](auto& context) {
    EXPECT_THAT(context.result, Not(IsSuccessful()));
    finished.Notify();
  };

  ASSERT_THAT(subject_.PerformRequest(http_context), IsSuccessful());

  finished.WaitForNotification();
}

}  // namespace
}  // namespace google::scp::core::test
