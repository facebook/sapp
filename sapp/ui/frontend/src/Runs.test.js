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
import TestRenderer from 'react-test-renderer';
import { MockedProvider } from '@apollo/client/testing';
import Runs, {RunsQuery} from './Runs';

const {act} = TestRenderer;

test("Renders runs", async () => {
  // Mock window.matchMedia
  window.matchMedia = window.matchMedia || function() {
    return {
      matches: false,
      addListener: function() {},
      removeListener: function() {}
    };
  };

  const mock = {
    request: {
      query: RunsQuery,
    },
    result: {
      data: {
        runs: {
          edges: [{
            node: {
              run_id: "1",
              date: "Dummy date",
            },
          }],
        },
      },
    },
  };

  const component = TestRenderer.create(
    <MockedProvider mocks={[mock]}>
      <Runs/>
    </MockedProvider>
  );

  // Mocked provider hasn't populated the results yet. Use it to test loading
  let tree = component.toJSON();
  expect(tree).toMatchSnapshot();

  /**
   * Await a zero-millisecond timeout. This delays the checks until the next
   * "tick" of the event loop, which gives MockedProvider an opportunity to
   * populate the mocked result
   */
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
  tree = component.toJSON();
  expect(tree).toMatchSnapshot()
});
