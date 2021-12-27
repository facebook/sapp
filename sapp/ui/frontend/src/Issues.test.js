/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 * @flow
 */

import React from 'react';
import TestRenderer from 'react-test-renderer';
import { MockedProvider } from '@apollo/client/testing';
import Issues, { IssueQuery } from './Issues';
import { Issue, IssueSkeleton } from './Issue';
import FilterControls, { filtersQuery } from './Filter';

const {act} = TestRenderer;

test("Renders issues and filters", async () => {
  // Mock window.matchMedia
  window.matchMedia = window.matchMedia || function() {
    return {
      matches: false,
      addListener: function() {},
      removeListener: function() {}
    };
  };

  const mockIssues = {
    edges: [{
      node: {
        issue_id: "1",
        issue_instance_id: "11",
        code: 6065,
        message: "This is a test issue",
        callable: "run.test",
        filename: "tests.js",
        location: "26|11|12",
        sources: ["TestSource"],
        source_names: ["TestSource"],
        sinks: ["TestSink"],
        sink_names: ["TestSink"],
        status: "Uncategorized",
        features: ["always-via:test"],
        is_new_issue: false,
        min_trace_length_to_sources: 0,
        min_trace_length_to_sinks: 0,
        first_seen: "2001-02-24 16:31:12.2402201",
        warning_message: "this is a test warning message",
      },
    }],
    pageInfo: {
      endCursor: "TestCursor",
    },
  };

  /**
   * There are only 2 requests, but one of the requests sometimes
   * occur with varrying variables, hence for issues, we have
   * two requests, and one for filters making total of 3 mocks
   */
  const mocks = [{
    request: {
      query: IssueQuery,
      variables: {
        run_id: "0",
        offset:0,
      },
    },
    result: {
      data: {
        issues: mockIssues,
      },
    },
  },
  {
    request: {
      query: IssueQuery,
      variables: {
        run_id: "0",
        features: [{mode:"all of",features:[]}],
        min_trace_length_to_sources: undefined,
        max_trace_length_to_sources: undefined,
        min_trace_length_to_sinks: undefined,
        max_trace_length_to_sinks: undefined,
        offset:0,
      },
    },
    result: {
      data: {
        issues: mockIssues,
      },
    },
  },
  {
    request: {
      query: filtersQuery,
    },
    result: {
      data: {
        filters: {
          edges: [{
            node: {
              name: "Test Filter",
              description: "Test description",
              json: "{}",
            },
          }],
        },
      },
    },
  }];

  const match = {
    params: {
      run_id: "0",
    },
  };

  const component = TestRenderer.create(
    <MockedProvider mocks={mocks}>
      <Issues match={match}/>
    </MockedProvider>
  );

  // Mocked provider hasn't populated the results yet. Use it to test loading
  let tree = component.toJSON();
  expect(tree[1].children.join('')).toContain(
    TestRenderer.create(<IssueSkeleton/>)
  );
  expect(tree).toMatchSnapshot();

  /**
   * Await a zero-millisecond timeout. This delays the checks until the next
   * "tick" of the event loop, which gives MockedProvider an opportunity to
   * populate the mocked result. Await two ticks because there are two
   * `useQuery` functions called in Issues.js. First tick renders the filters
   * and the second tick renders the issue(s).
   */
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  tree = component.toJSON();
  const instance = component.root;
  expect(instance.findByType(Issue).props.issue.callable).toBe('run.test');
  expect(instance.findByType(FilterControls).props.refetching).toBe(false);
  expect(tree).toMatchSnapshot();
});
