/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 * @flow
 */

import React from 'react';
import {useQuery, gql} from '@apollo/client';
import {
  Alert,
  Breadcrumb,
  Card,
  Col,
  Layout,
  Progress,
  Row,
  Skeleton,
  Statistic,
  Table,
  Tag
} from 'antd';
import {Column} from '@ant-design/charts'

export const StatisticsQuery = gql`
  query Metrics($run_id: Int!) {
    metrics(run_id: $run_id) {
      edges {
        node {
          triaged_count
          issues_count
          warning_codes_and_statuses
          common_features
          common_callables
          common_callables_in_traces
          files_count
        }
      }
    }
  }
`;

export default function Statistics(props: $ReadOnly<{}>): React$Node {
  const run_id = props.match.params.run_id;

  const {loading, error, data} = useQuery(StatisticsQuery, {
    variables: {run_id}
  });

  var content = null;
  if (error) {
    content = <Alert>error</Alert>
  } else if(loading) {
    content = <Skeleton></Skeleton>
  } else {
    const metrics = data.metrics.edges[0].node;
    const filesTableColumns = [
      {
        title: 'File name',
        dataIndex: 'file',
      },
      {
        title: 'Count',
        dataIndex: 'count',
        defaultSortOrder: 'descend',
        sorter: (a,b) => a.count - b.count,
      }
    ];
    const filesData = metrics.files_count.map(data => (
      {
        file: data[0],
        count: data[1],
      }
    ));
    const warning_codes_graph_config = {
      data: metrics.warning_codes_and_statuses.map(item => ({
        warning_code: item[0],
        type: item[1],
        count: Number(item[2]),
      })),
      xField: 'warning_code',
      yField: 'count',
      seriesField: 'type',
      isStack: true,
      label : {
        position : 'middle',
        layout : [
          { type : 'interval-adjust-position' },
          { type : 'interval-hide-overlap' },
          { type : 'adjust-color' },
        ],
      },
    };
    content = (
      <>
        <Row gutter={[16,16]}>
          <Col span={12}>
            <Card loading={loading}>
              <Row>
                <Col span={12}>
                  <Statistic
                    title="Triaged Issues"
                    value={metrics.triaged_count}
                    suffix={`/ ${metrics.issues_count}`} />
                </Col>
                <Col span={12}>
                  <Progress
                    type="circle"
                    percent={(
                      metrics.triaged_count / (metrics.issues_count || 1)
                    ).toPrecision(2) * 100}
                    style = {{float: 'right'}}/>
                </Col>
              </Row>
            </Card>
          </Col>
          <Col span={12}>
            <Card loading={loading} title="Common Features">
              <Row gutter={[4, 4]}>
                <Col span={8}>Callables:</Col>
                <Col span={16}>
                  { metrics.common_callables.length > 0 ?
                    metrics.common_callables.map(callable =>
                      <Tag color="blue">{callable}</Tag>
                    ):
                    <Tag>No common callables</Tag>
                  }
                </Col>
              </Row>
              <Row gutter={[4, 4]}>
                <Col span={8}>Features:</Col>
                <Col span={16}>
                  { metrics.common_features.length > 0 ?
                    metrics.common_features.map(feature =>
                      <Tag color="purple">{feature}</Tag>
                    ):
                    <Tag>No common features</Tag>
                  }
                </Col>
              </Row>
              <Row gutter={[4, 4]}>
                <Col span={8}>Callables in traces:</Col>
                <Col span={16}>
                  { metrics.common_callables_in_traces.length > 0 ?
                    metrics.common_callables_in_traces.map(callable =>
                      <Tag color="geekblue">{callable}</Tag>
                  ):
                    <Tag>No common callables in traces</Tag>
                  }
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>
        <Row gutter={[16,16]}>
          <Col span={12}>
            <Card loading={loading} title="Warning codes and statuses">
              <Column {...warning_codes_graph_config} />
            </Card>
          </Col>
          <Col span={12}>
            <Card loading={loading} title="Files in traces">
              <Table columns={filesTableColumns} dataSource={filesData}/>
            </Card>
          </Col>
        </Row>
      </>
    )
  }

  return (
    <>
      <Breadcrumb style={{ margin: '16px 0' }}>
        <Breadcrumb.Item href="/runs">Runs</Breadcrumb.Item>
        <Breadcrumb.Item>Run {run_id}</Breadcrumb.Item>
      </Breadcrumb>
      <Layout>
        {content}
      </Layout>
    </>
  );
}
