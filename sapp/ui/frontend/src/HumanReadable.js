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
import {Tooltip, Typography} from 'antd';
const {Text} = Typography;

export function HumanReadablePort(props: $ReadOnly<{port: string}>) {
  // TODO(T71492980): hard-coding heuristics for Pysa right now.
  var port = props.port;

  var access = '';
  var accesses = port.match(/(\[.*\])+/);
  if (accesses) {
    port = port.slice(0, port.length - accesses[1].length);
    accesses = accesses[1]
      .split(']')
      .filter(access => access !== '')
      .map(access => access.slice(1))
      .map(access => <Text code>{access}</Text>);
    access = <> accessing {accesses}</>;
  }

  if (port === 'result') {
    port = 'returns';
  }
  const formal_match = port.match(/formal\((.*)\)/);
  if (formal_match) {
    port = (
      <>
        into parameter <Text code>{formal_match[1]}</Text>
      </>
    );
  }

  return (
    <Text type="secondary">
      {port}
      {access}
    </Text>
  );
}

function makeDalvikParametersHumanReadable(input: string): Array<string> {
  if (input.length == 0) {
    return [];
  }

  if (!input.startsWith('L')) {
    return [makeDalvikClassHumanReadable(input[0])].concat(
      makeDalvikParametersHumanReadable(input.slice(1)),
    );
  } else {
    const split = input.split(';');
    return [makeDalvikClassHumanReadable(split[0] + ';')].concat(
      makeDalvikParametersHumanReadable(split.slice(1).join(';')),
    );
  }
}

export function makeDalvikClassHumanReadable(input: string): string {
  switch (input) {
    case 'I': return 'int';
    case 'V': return 'void';
    case 'Z': return 'boolean';
  }

  const split = input.split('/');
  const last = split[split.length - 1];
  return last[last.length-1] === ';' ? last.slice(0, -1) : last;
}

function makeDalvikHumanReadable(input: string): string {
  const match = input.match(/(.*);\.(.*):\((.*)\)(.*)/);
  if (match == null) {
    return input;
  }

  const clazz = makeDalvikClassHumanReadable(match[1]);
  const method = match[2];
  const return_type = makeDalvikClassHumanReadable(match[4]);
  const parameters = makeDalvikParametersHumanReadable(match[3]).join(', ');

  return `${return_type} ${clazz}.${method}(${parameters})`;
}

export function HumanReadable(
  props: $ReadOnly<{
    input: string,
    separator?: string,
    threshold?: number,
    code?: boolean,
  }>,
): React$Node {
  const separator = props.separator || '.';
  const threshold = props.threshold || 50;

  var readable = props.input;

  if (readable.includes(';')) {
    // Assume this is a Dalvik identifier
    readable = makeDalvikHumanReadable(readable);
  }

  if (readable.length > threshold) {
    // Attempt to construct `module...Class.method`.
    const split = readable.split(separator);
    if (split.length > 3) {
      readable = `${split[0]}${separator}[...]${separator}${
        split[split.length - 2]
      }.${split[split.length - 1]}`;
    }
  }
  return (
    <Tooltip title={props.input}>
      <Text code={props.code || false} style={{wordBreak: 'break-all'}}>
        {readable}
      </Text>
    </Tooltip>
  );
}
