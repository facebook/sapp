/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 * @flow
 */

import React, { useEffect, useState } from 'react';
import { useQuery, gql } from '@apollo/client';
import { Button, Layout, Modal, Breadcrumb } from 'antd';
import FilterControls, { loadFilter, filterToVariables } from './Filter';
import { Issue, IssueSkeleton } from './Issue.js';

function IssuesList(props: $ReadOnly<{|
  issues: any,
  run_id: number,
  onFetchMore: any,
  canFetchMore: boolean
|}>): React$Node {
  return (
    <>
      {props.issues.map(({ node }) => (
        <>
          <Issue run_id={props.run_id} issue={node} />
          <br />
        </>
      ))}
      <div style={{ textAlign: 'center' }}>
        <Button
          type="dashed"
          disabled={!props.canFetchMore}
          onClick={props.onFetchMore}>
          Load More...
        </Button>
      </div>
    </>
  );
}

const PAGE_SIZE = 20;

export const IssueQuery = gql`
  query Issue(
    $after: String
    $run_id: Int!
    $codes: [Int]
    $paths: [String]
    $callables: MatchesIsField
    $source_names: MatchesIsField
    $source_kinds: MatchesIsField
    $sink_names: MatchesIsField
    $sink_kinds: MatchesIsField
    $statuses: [String]
    $features: [FeatureCondition]
    $min_trace_length_to_sinks: Int
    $max_trace_length_to_sinks: Int
    $min_trace_length_to_sources: Int
    $max_trace_length_to_sources: Int
    $is_new_issue: Boolean
  ) {
    issues(
      first: ${PAGE_SIZE}
      after: $after
      run_id: $run_id
      codes: $codes
      paths: $paths
      callables: $callables
      source_names: $source_names
      source_kinds: $source_kinds
      sink_names: $sink_names
      sink_kinds: $sink_kinds
      statuses: $statuses
      features: $features
      min_trace_length_to_sinks: $min_trace_length_to_sinks
      max_trace_length_to_sinks: $max_trace_length_to_sinks
      min_trace_length_to_sources: $min_trace_length_to_sources
      max_trace_length_to_sources: $max_trace_length_to_sources
      is_new_issue: $is_new_issue
    ) {
      edges {
        node {
          issue_id
          issue_instance_id
          code
          message
          callable
          filename
          location
          sources
          source_names
          sinks
          sink_names
          status
          features
          is_new_issue
          min_trace_length_to_sources
          min_trace_length_to_sinks
          detected_time
          warning_message
        }
      }
      pageInfo {
        endCursor
      }
    }
  }
`;

const Issues = (props: $ReadOnly<{ match: any }>): React$Node => {
  const run_id = props.match.params.run_id;

  const savedFilter = loadFilter();
  const variables = savedFilter ? filterToVariables(savedFilter) : null;

  const [oldData, setOldData] = useState(null);
  const [refetching, setRefetching] = useState(false);

  const [cursor, setCursor] = useState(null);
  const { loading, error, data, fetchMore, refetch } = useQuery(IssueQuery, {
    variables: { ...variables, run_id, offset: 0 },
  });
  const [moreData, setMoreData] = useState([]);
  const [canFetchMore, setCanFetchMore] = useState(true);

  // Ridiculous workaround for https://github.com/apollographql/react-apollo/issues/3709.
  const clearAndRefetch = values => {
    setOldData(data);
    setRefetching(true);
    refetch(values);
  };
  useEffect(() => {
    if (data !== oldData) {
      setRefetching(false);
    }
  }, [data, oldData, setOldData]);

  var content = null;
  if (error) {
    content = (
      <Modal title="Error" visible={true} footer={null}>
        <p>{error.toString()}</p>
      </Modal>
    );
  } else if (loading) {
    content = <IssueSkeleton />;
  } else {
    const issues = data.issues.edges || [];
    content = (
      <IssuesList
        run_id={run_id}
        issues={[...issues, ...moreData]}
        onFetchMore={() => {
          fetchMore({
            variables: {
              after: cursor || data.issues.pageInfo.endCursor,
            }
          }).then(fetchMoreResult => {
            const issues = fetchMoreResult.data.issues;
            setCursor(issues.pageInfo.endCursor);
            setMoreData([...moreData, ...issues.edges])
            setCanFetchMore(issues.edges.length == PAGE_SIZE)
          });
        }}
        canFetchMore={issues.length >= PAGE_SIZE && canFetchMore}
      />
    );
  }

  return (
    <>
      <Breadcrumb style={{ margin: '16px 0' }}>
        <Breadcrumb.Item href="/runs">Runs</Breadcrumb.Item>
        <Breadcrumb.Item>Run {run_id}</Breadcrumb.Item>
      </Breadcrumb>
      <Layout>
        <Layout style={{ paddingRight: '24px' }}>
          {content}
        </Layout>
        <FilterControls
          refetch={clearAndRefetch}
          refetching={refetching} />
      </Layout>
    </>
  );
};

export default Issues;
