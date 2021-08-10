/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 * @flow
 */

import React, {useState} from 'react';
import {useQuery, useMutation, gql} from '@apollo/client';
import {Breadcrumb, Card, Col, Modal, Row, Typography} from 'antd';
import {DeleteOutlined, LoadingOutlined, SyncOutlined} from '@ant-design/icons';
import {clearFilter} from './Filter';

const {Text, Link} = Typography;

type RunDescription = $ReadOnly<{
  run_id: number,
  date: string,
}>;

function Run(props: $ReadOnly<{run: RunDescription}>): React$Node {
  const gutter = [8, 8];
  const [showRun, setShowRun] = useState(true);

  const Label = (props: $ReadOnly<{children: React$Node}>): React$Node => {
    return (
      <Col span={4} style={{textAlign: 'right'}}>
        <Text type="secondary">{props.children}</Text>
      </Col>
    );
  };
  const Item = (props: $ReadOnly<{children: React$Node}>): React$Node => {
    return (
      <Col span={20}>
        <Text type="secondary">{props.children}</Text>
      </Col>
    );
  };

  const deleteRunMutation = gql`
    mutation DeleteRun($id: ID!) {
      delete_run(input: {id: $id}) {
        clientMutationId
      }
    }
  `;

  const [deleteRun, {error: deleteError}] = useMutation(
    deleteRunMutation,
    {
      onCompleted() {
        setShowRun(false)
      }
    }
  );

  const onDelete = (): void => {
    deleteRun({variables: {id: props.run.run_id}});
  };

  if(deleteError) {
    Modal.error({title: 'Unable to delete run ', content: deleteError.toString()});
  }

  const contents = (
    <Col span={8}>
      <Card
        size="small"
        title={
          <>
            <SyncOutlined style={{marginRight: '.5em'}} />
            Run {props.run.run_id}
          </>
        }
        extra={
          <Link
            onClick={() => clearFilter()}
            href={`/run/${props.run.run_id}`}>
            Issues
          </Link>
        }
        actions={[
          <DeleteOutlined onClick={onDelete}/>
        ]}>
        <Row gutter={gutter}>
          <Label>Date</Label>
          <Item>
            <Text code>{props.run.date}</Text>
          </Item>
        </Row>
      </Card>
      <br />
    </Col>
  )

  return (
    <>
      { showRun ? contents : null }
    </>
  );
}

export const RunsQuery = gql`
  query Run {
    runs {
      edges {
        node {
          run_id
          date
        }
      }
    }
  }
`;

export default function Runs(props: $ReadOnly<{}>): React$Node {
  const {loading, error, data} = useQuery(RunsQuery);

  if (error) {
    Modal.error({title: 'Unable to load run data', content: error.toString()});
    return null;
  }

  var content = null;
  if (loading) {
    content = (
      <Col span={8}>
        <Card>
          <div style={{height: '12em', textAlign: 'center', paddingTop: '5em'}}>
            <Text type="secondary">
              <LoadingOutlined />
              <br />
              Loading runs...
            </Text>
          </div>
        </Card>
      </Col>
    );
  }

  if (data) {
    content = data.runs.edges.map(edge => <Run run={edge.node} />);
  }

  return (
    <>
      <Breadcrumb style={{margin: '16px 0'}}>
        <Breadcrumb.Item>Runs</Breadcrumb.Item>
      </Breadcrumb>
      <Row gutter={16}>
        {content}
      </Row>
    </>
  );
}
