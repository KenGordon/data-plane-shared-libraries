/*
 * Copyright 2023 Google LLC
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

#include "public/cpio/utils/metric_aggregation/src/metric_instance_factory.h"

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/synchronization/blocking_counter.h"
#include "absl/synchronization/notification.h"
#include "core/async_executor/src/async_executor.h"
#include "core/config_provider/mock/mock_config_provider.h"
#include "core/interface/async_context.h"
#include "core/interface/configuration_keys.h"
#include "core/message_router/src/error_codes.h"
#include "core/message_router/src/message_router.h"
#include "core/test/utils/auto_init_run_stop.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "public/cpio/mock/metric_client/mock_metric_client.h"
#include "public/cpio/proto/metric_service/v1/metric_service.pb.h"
#include "public/cpio/utils/metric_aggregation/interface/type_def.h"

using google::cmrt::sdk::metric_service::v1::Metric;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutor;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::kAggregatedMetricIntervalMs;
using google::scp::core::kDefaultAggregatedMetricIntervalMs;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::config_provider::mock::MockConfigProvider;
using google::scp::core::test::AutoInitRunStop;
using google::scp::cpio::MetricUnit;
using google::scp::cpio::MockMetricClient;
using ::testing::Contains;
using ::testing::Key;
using ::testing::StrEq;

namespace {
constexpr char kMetricName[] = "FrontEndRequestCount";
constexpr char kMetricNameUpdate[] = "NewMetricName";
constexpr char kMetricValue[] = "1234";
constexpr char kOneIncrease[] = "1";
constexpr char kNamespace[] = "PBS";
constexpr int kAggregatedIntervalMs = 1;
constexpr char kEventCodeKey[] = "event_key";

}  // namespace

namespace google::scp::cpio {

class MetricInstanceFactoryTest : public testing::Test {
 protected:
  MetricInstanceFactoryTest() {
    mock_metric_client_ = std::make_shared<MockMetricClient>();
    real_async_executor_ = std::make_shared<AsyncExecutor>(
        2 /* thread count */, 1000 /* queue capacity */);

    auto mock_config_provider = std::make_shared<MockConfigProvider>();

    mock_config_provider->SetInt(std::string(kAggregatedMetricIntervalMs),
                                 kAggregatedIntervalMs);
    EXPECT_SUCCESS(real_async_executor_->Init());
    EXPECT_SUCCESS(real_async_executor_->Run());
    metric_factory_ = std::make_shared<MetricInstanceFactory>(
        real_async_executor_, mock_metric_client_, mock_config_provider);
  }

  ~MetricInstanceFactoryTest() { EXPECT_SUCCESS(real_async_executor_->Stop()); }

  std::shared_ptr<AsyncExecutorInterface> real_async_executor_;
  std::shared_ptr<MetricInstanceFactoryInterface> metric_factory_;
  std::shared_ptr<MockMetricClient> mock_metric_client_;
};

TEST_F(MetricInstanceFactoryTest, ConstructSimpleMetricInstance) {
  auto metric_info =
      MetricDefinition(kMetricName, MetricUnit::kCount, kNamespace);

  auto simple_metric =
      metric_factory_->ConstructSimpleMetricInstance(std::move(metric_info));

  AutoInitRunStop to_handle_simple_metric(*simple_metric);
  {
    Metric metric_received;
    absl::Notification schedule_is_called;
    EXPECT_CALL(*mock_metric_client_, PutMetrics).WillOnce([&](auto context) {
      metric_received.CopyFrom(context.request->metrics(0));
      schedule_is_called.Notify();
      context.result = SuccessExecutionResult();
      context.Finish();
      return context.result;
    });

    simple_metric->Push(kMetricValue);
    schedule_is_called.WaitForNotification();

    EXPECT_THAT(metric_received.name(), StrEq(kMetricName));
    EXPECT_EQ(metric_received.unit(),
              cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_COUNT);
    EXPECT_THAT(metric_received.value(), StrEq(kMetricValue));
  }

  {
    auto metric_info_override = MetricDefinition(
        kMetricNameUpdate, MetricUnit::kMilliseconds, kNamespace);
    Metric metric_received;
    absl::Notification schedule_is_called;
    EXPECT_CALL(*mock_metric_client_, PutMetrics).WillOnce([&](auto context) {
      metric_received.CopyFrom(context.request->metrics(0));
      schedule_is_called.Notify();
      context.result = SuccessExecutionResult();
      context.Finish();
      return context.result;
    });

    simple_metric->Push(kMetricValue, metric_info_override);
    schedule_is_called.WaitForNotification();

    EXPECT_THAT(metric_received.name(), StrEq(kMetricNameUpdate));
    EXPECT_EQ(
        metric_received.unit(),
        cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_MILLISECONDS);
    EXPECT_THAT(metric_received.value(), StrEq(kMetricValue));
  }
}

TEST_F(MetricInstanceFactoryTest, ConstructAggregateMetricInstance) {
  auto metric_info =
      MetricDefinition(kMetricName, MetricUnit::kCount, kNamespace);

  auto aggregate_metric =
      metric_factory_->ConstructAggregateMetricInstance(std::move(metric_info));

  AutoInitRunStop to_handle_aggregate_metric(*aggregate_metric);

  {
    Metric metric_received;
    absl::Notification schedule_is_called;
    EXPECT_CALL(*mock_metric_client_, PutMetrics).WillOnce([&](auto context) {
      metric_received.CopyFrom(context.request->metrics(0));
      schedule_is_called.Notify();
      context.result = SuccessExecutionResult();
      context.Finish();
      return context.result;
    });

    aggregate_metric->Increment();
    schedule_is_called.WaitForNotification();

    EXPECT_THAT(metric_received.name(), StrEq(kMetricName));
    EXPECT_EQ(metric_received.unit(),
              cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_COUNT);
    EXPECT_THAT(metric_received.value(), StrEq(kOneIncrease));
  }

  {
    Metric metric_received;
    absl::Notification schedule_is_called;
    EXPECT_CALL(*mock_metric_client_, PutMetrics).WillOnce([&](auto context) {
      metric_received.CopyFrom(context.request->metrics(0));
      schedule_is_called.Notify();
      context.result = SuccessExecutionResult();
      context.Finish();
      return context.result;
    });

    aggregate_metric->IncrementBy(std::stoi(kMetricValue));
    schedule_is_called.WaitForNotification();

    EXPECT_THAT(metric_received.name(), StrEq(kMetricName));
    EXPECT_EQ(metric_received.unit(),
              cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_COUNT);
    EXPECT_THAT(metric_received.value(), StrEq(kMetricValue));
  }
}

TEST_F(MetricInstanceFactoryTest,
       ConstructAggregateMetricInstanceWithEventCodeList) {
  auto metric_info =
      MetricDefinition(kMetricName, MetricUnit::kCount, kNamespace);
  std::vector<std::string> event_code_list = {"value1", "value2", "value3"};

  auto aggregate_metric = metric_factory_->ConstructAggregateMetricInstance(
      std::move(metric_info), event_code_list, kEventCodeKey);

  AutoInitRunStop to_handle_aggregate_metric(*aggregate_metric);

  {
    absl::BlockingCounter schedule_is_called(3);
    EXPECT_CALL(*mock_metric_client_, PutMetrics)
        .WillRepeatedly([&](auto context) {
          EXPECT_THAT(context.request->metrics(0).name(), StrEq(kMetricName));
          EXPECT_EQ(
              context.request->metrics(0).unit(),
              cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_COUNT);
          EXPECT_THAT(context.request->metrics(0).value(), StrEq(kOneIncrease));
          schedule_is_called.DecrementCount();
          context.result = SuccessExecutionResult();
          context.Finish();
          return context.result;
        });

    for (const auto& event_code : event_code_list) {
      aggregate_metric->Increment(event_code);
    }

    schedule_is_called.Wait();
  }

  {
    absl::BlockingCounter schedule_is_called(3);
    EXPECT_CALL(*mock_metric_client_, PutMetrics)
        .WillRepeatedly([&](auto context) {
          EXPECT_THAT(context.request->metrics(0).name(), StrEq(kMetricName));
          EXPECT_EQ(
              context.request->metrics(0).unit(),
              cmrt::sdk::metric_service::v1::MetricUnit::METRIC_UNIT_COUNT);
          EXPECT_THAT(context.request->metrics(0).value(), StrEq(kMetricValue));
          EXPECT_THAT(context.request->metrics(0).labels(),
                      Contains(Key(kEventCodeKey)));
          schedule_is_called.DecrementCount();
          context.result = SuccessExecutionResult();
          context.Finish();
          return context.result;
        });

    for (const auto& event_code : event_code_list) {
      aggregate_metric->IncrementBy(std::stoi(kMetricValue), event_code);
    }

    schedule_is_called.Wait();
  }
}

}  // namespace google::scp::cpio
