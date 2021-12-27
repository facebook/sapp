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
import { Trace, IssueQuery, InitialTraceFramesQuery } from './Traces'
import { Issue } from './Issue';
import { SourceQuery } from './Source';

const {act} = TestRenderer;

test("Renders traces", async () => {
  // Mock window.matchMedia
  window.matchMedia = window.matchMedia || function() {
    return {
      matches: false,
      addListener: function() {},
      removeListener: function() {}
    };
  };
  // Mock document.body.createTextRange
  document.body.createTextRange = document.body.createTextRange || function() {
    return {
      setStart: () => {},
      setEnd: () => {},
      getBoundingClientRect: () => {return {length: 0}},
      getClientRects: () => {return {length: 0}},
      commonAncestorContainer: {
        nodeName: 'BODY',
        ownerDocument: document,
      },
    }
  };

  const mockIssue = {
    edges: [{
      node: {
        issue_id: "1",
        issue_instance_id: "11",
        code: 6065,
        message: "This is a test issue",
        callable: "run.test",
        filename: "tests.js",
        location: "1|0|0",
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
        similar_issues: [{"issue_id": "2", "score": "0.75"}],
      },
    }],
    pageInfo: {
      endCursor: "TestCursor",
    },
  };

  const mockPreTrace = {
    edges: [{
      node: {
        frame_id: "116",
        callee: "TestCallee",
        callee_id: "19",
        filename: "test.js",
        callee_location: "1|0|0",
        trace_length: 0,
        is_leaf: true,
      },
    }]
  };

  const mockPostTrace = {
    edges: [{
      node: {
        frame_id: "115",
        callee: "TestCallee",
        callee_id: "4",
        filename: "test.js",
        callee_location: "1|0|0",
        trace_length: 0,
        is_leaf: true,
      },
    }]
  };

  const mockSource = {
    edges: [{
      node: {
        contents: "test\n\n\ntest",
        editor_link: null,
      },
    }]
  };

  const mocks = [{
    request: {
      query: IssueQuery,
      variables: {
        run_id: "0",
        issue_instance_id: 11,
      },
    },
    result: {
      data: {
        issues: mockIssue,
      },
    },
  },
  {
    request: {
      query: InitialTraceFramesQuery,
      variables: {
        issue_instance_id: 11,
        kind: "precondition"
      },
    },
    result: {
      data: {
        initial_trace_frames: mockPreTrace,
      },
    },
  },
  {
    request: {
      query: InitialTraceFramesQuery,
      variables: {
        issue_instance_id: 11,
        kind: "postcondition"
      },
    },
    result: {
      data: {
        initial_trace_frames: mockPostTrace,
      },
    },
  },
  {
    request: {
      query: SourceQuery,
      variables: {
        path: "test.js"
      },
    },
    result: {
      data: {
        file: mockSource,
      },
    },
  }];

  const match = {
    params: {
      run_id: "0",
      issue_instance_id: 11,
    },
  };

  const component = TestRenderer.create(
    <MockedProvider mocks={mocks}>
      <Trace match={match}/>
    </MockedProvider>
  );

  // Mocked provider hasn't populated the results yet. Use it to test loading
  let tree = component.toJSON();
  expect(tree).toMatchSnapshot();

  /**
   * Await a zero-millisecond timeout. This delays the checks until the next
   * "tick" of the event loop, which gives MockedProvider an opportunity to
   * populate the mocked result. Await three ticks because there are three
   * `useQuery` functions called in Traces.js. First tick renders the issue,
   * second renders the pre-condition trace, the third renders the
   * post-condition, and the last the source.
   */
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  tree = component.toJSON();
  const instance = component.root;
  expect(instance.findByType(Issue).props.issue.callable).toBe('run.test');
  expect(tree).toMatchSnapshot();
});
