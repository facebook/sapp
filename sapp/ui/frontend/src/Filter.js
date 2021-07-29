/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 * @flow
 */

import React, {useState, useEffect} from 'react';
import {useQuery, useMutation, gql} from '@apollo/client';
import {
  Alert,
  AutoComplete,
  Checkbox,
  Collapse,
  Divider,
  Popover,
  Button,
  Form,
  Input,
  Layout,
  Menu,
  Modal,
  Row,
  Col,
  Select,
  Slider,
  Tooltip,
  Typography,
} from 'antd';
import {
  ExportOutlined,
  FieldTimeOutlined,
  FilterOutlined,
  PlusOutlined,
  MinusCircleOutlined,
  SettingOutlined,
  SaveOutlined,
  DeleteOutlined,
  ClearOutlined,
} from '@ant-design/icons';
import {Documentation} from './Documentation.js';
import {statusMap} from './Issue.js';

import './Filter.css';

const {Option} = Select;
const {Panel} = Collapse;
const {Sider} = Layout;
const {SubMenu} = Menu;
const {Text} = Typography;

type FeatureCondition = {
  mode: string,
  features: $ReadOnlyArray<string>,
};

type FilterDescription = {
  name?: string,
  description?: string,
  codes?: $ReadOnlyArray<number>,
  paths?: $ReadOnlyArray<string>,
  source_names?: $ReadOnlyArray<string>,
  source_kinds?: $ReadOnlyArray<string>,
  statuses?: $ReadOnlyArray<string>,
  sink_names?: $ReadOnlyArray<string>,
  sink_kinds?: $ReadOnlyArray<string>,
  callables?: $ReadOnlyArray<string>,
  features?: $ReadOnlyArray<FeatureCondition>,
  traceLengthFromSources?: $ReadOnlyArray<number>,
  traceLengthToSinks?: $ReadOnlyArray<number>,
  is_new_issue?: boolean,
};

const emptyFilter = {
  features: [{mode: 'all of', features: []}],
};

const infiniteTraceLength = 31;
const gutter = [8, 8];

const filterEqual = (
  left: FilterDescription,
  right: FilterDescription,
): boolean => {
  Object.keys(left).forEach(key =>
    left[key] === undefined ? delete left[key] : {},
  );
  Object.keys(right).forEach(key =>
    right[key] === undefined ? delete right[key] : {},
  );
  return JSON.stringify(left) === JSON.stringify(right);
};

const Label = (props: $ReadOnly<{label: string}>): React$Node => {
  const title = props.label
    .split(/(?=[A-Z])/)
    .map(value => value.charAt(0).toUpperCase() + value.slice(1))
    .join(' ');
  return (
    <>
      <Tooltip title={Documentation.filter[props.label]}>
        <Text type="secondary"> {title}</Text>
      </Tooltip>
    </>
  );
};

const Codes = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const codesQuery = gql`
    query Codes {
      codes {
        edges {
          node {
            code
          }
        }
      }
    }
  `;
  const {data: codesData} = useQuery(codesQuery);
  const allCodes = (codesData?.codes?.edges || []).map(edge => edge.node.code);

  return (
    <>
      <Label label="codes" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.codes}
            options={allCodes.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={codes =>
              props.setCurrentFilter({...props.currentFilter, codes})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const Paths = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const pathsQuery = gql`
    query Paths {
      paths {
        edges {
          node {
            path
          }
        }
      }
    }
  `;
  const {data: pathsData} = useQuery(pathsQuery);
  const allPaths = (pathsData?.paths?.edges || []).map(edge => edge.node.path);

  return (
    <>
      <Label label="paths" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.paths}
            options={allPaths.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={paths =>
              props.setCurrentFilter({...props.currentFilter, paths})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const SourceNames = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const sourceNamesQuery = gql`
    query SourceNames {
      source_names {
        edges {
          node {
            source_name
          }
        }
      }
    }
  `;
  const {data: sourceNamesData} = useQuery(sourceNamesQuery);
  const allSourceNames = (sourceNamesData?.source_names?.edges || []).map(edge => edge.node.source_name);

  return (
    <>
      <Label label="name" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.source_names}
            options={allSourceNames.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={source_names =>
              props.setCurrentFilter({...props.currentFilter, source_names})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const SourceKinds = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const sourceKindsQuery = gql`
    query SourceKinds {
      source_kinds {
        edges {
          node {
            source_kind
          }
        }
      }
    }
  `;
  const {data: sourceKindsData} = useQuery(sourceKindsQuery);
  const allSourceKinds = (sourceKindsData?.source_kinds?.edges || []).map(edge => edge.node.source_kind);

  return (
    <>
      <Label label="kind" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.source_kinds}
            options={allSourceKinds.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={source_kinds =>
              props.setCurrentFilter({...props.currentFilter, source_kinds})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const SinkNames = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const sinkNamesQuery = gql`
    query SinkNames {
      sink_names {
        edges {
          node {
            sink_name
          }
        }
      }
    }
  `;
  const {data: sinkNamesData} = useQuery(sinkNamesQuery);
  const allSinkNames = (sinkNamesData?.sink_names?.edges || []).map(edge => edge.node.sink_name);

  return (
    <>
      <Label label="name" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.sink_names}
            options={allSinkNames.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={sink_names =>
              props.setCurrentFilter({...props.currentFilter, sink_names})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const SinkKinds = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const sinkKindsQuery = gql`
    query SinkKinds {
      sink_kinds {
        edges {
          node {
            sink_kind
          }
        }
      }
    }
  `;
  const {data: sinkKindsData} = useQuery(sinkKindsQuery);
  const allSinkKinds = (sinkKindsData?.sink_kinds?.edges || []).map(edge => edge.node.sink_kind);

  return (
    <>
      <Label label="kind" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.sink_kinds}
            options={allSinkKinds.map(value => ({value}))}
            style={{width: '100%'}}
            onChange={sink_kinds =>
              props.setCurrentFilter({...props.currentFilter, sink_kinds})
            }
          />
        </Col>
      </Row>
    </>
  );
};

const Statuses = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const statusQuery = gql`
    query Statuses {
      statuses {
        edges {
          node {
            status
          }
        }
      }
    }
  `;
  const {data: statusData} = useQuery(statusQuery);
  const allStatusOptions = (
    statusData?.statuses?.edges || []
  ).map(edge =>
    edge.node.status.replace("IssueStatus.", "")
  ).map(status =>
    <Option value={status}>{statusMap[status]}</Option>
  );

  return (
    <>
      <Label label="status" />
      <Row gutter={gutter}>
        <Col span={22}>
          <Select
            mode="multiple"
            value={props.currentFilter.statuses}
            style={{width: '100%'}}
            onChange={statuses =>
              props.setCurrentFilter({...props.currentFilter, statuses})
            }>
            {allStatusOptions}
          </Select>
        </Col>
      </Row>
    </>
  );
};

const Callables = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const [mode, setMode] = useState('is');
  const [inputValue, setInputValue] = useState(null);

  const callablesQuery = gql`
    query Callables {
      callables {
        edges {
          node {
            callable
          }
        }
      }
    }
  `;
  const {data: callablesData} = useQuery(callablesQuery);
  const allCallables = (callablesData?.callables?.edges || []).map(
    edge => edge.node.callable,
  );

  return (
    <>
      <Label label="callables" />
      <Row gutter={gutter}>
        <Col span={6}>
          <Select
            options={[{value: 'is'}, {value: 'matches'}]}
            value={mode}
            onChange={setMode}
            style={{width: '100%'}}
          />
        </Col>
        <Col span={16}>
          {mode === 'is' ? (
            <Select
              mode="multiple"
              value={props.currentFilter.callables}
              options={allCallables.map(value => ({value}))}
              style={{width: '100%'}}
              onChange={callables =>
                props.setCurrentFilter({...props.currentFilter, callables})
              }
            />
          ) : (
            <Input
              placeholder="regular experssion"
              style={{width: '100%'}}
              value={inputValue}
              onChange={event => {
                const value = event.target.value;
                setInputValue(value);
                const callables = allCallables.filter(callable =>
                  callable.match(value),
                );
                props.setCurrentFilter({...props.currentFilter, callables});
              }}
              suffix={
                <Tooltip
                  title={(props.currentFilter.callables || []).join('\n')}
                  placement="bottom">
                  <Text type="secondary" size="small">
                    {(props.currentFilter.callables || []).length}
                  </Text>
                </Tooltip>
              }
            />
          )}
        </Col>
      </Row>
    </>
  );
};

const Features = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const featuresQuery = gql`
    query Features {
      features {
        edges {
          node {
            feature
          }
        }
      }
    }
  `;
  const {data: featuresData} = useQuery(featuresQuery);
  const allFeatures = (featuresData?.features?.edges || []).map(
    edge => edge.node.feature,
  );

  const features = props.currentFilter.features || [];

  return (
    <>
      <Label label="features" />
      {features.map((feature, index) => {
        const updateFeature = update => {
          var newFeatures = [...features];
          newFeatures[index] = {...feature, ...update};
          props.setCurrentFilter({
            ...props.currentFilter,
            features: newFeatures,
          });
        };

        return (
          <Row gutter={gutter}>
            <Col span={6}>
              <Select
                options={[
                  {value: 'all of'},
                  {value: 'any of'},
                  {value: 'none of'},
                ]}
                value={feature.mode}
                style={{width: '100%'}}
                onChange={mode => updateFeature({mode})}
              />
            </Col>
            <Col span={16}>
              <Select
                mode="multiple"
                options={allFeatures.map(value => ({value}))}
                value={feature.features}
                onChange={features => updateFeature({features})}
                style={{width: '100%'}}
              />
            </Col>
            <Col span={2}>
              <Button
                type="text"
                onClick={() => {
                  props.setCurrentFilter({
                    ...props.currentFilter,
                    features: features.filter(
                      (_, filterIndex) => index !== filterIndex,
                    ),
                  });
                }}
                disabled={features.length < 2}
                icon={<MinusCircleOutlined />}
              />
            </Col>
          </Row>
        );
      })}
      <Row gutter={gutter}>
        <Col span={22}>
          <Button
            type="dashed"
            onClick={() => {
              props.setCurrentFilter({
                ...props.currentFilter,
                features: [...features, {mode: 'all of', features: []}],
              });
            }}
            icon={<PlusOutlined />}
            style={{width: '100%', marginTop: 5}}
            block>
            {' '}
            Add Condition
          </Button>
        </Col>
      </Row>
    </>
  );
};

const IsNewIssue = (
  props: $ReadOnly<{
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  return (
    <>
      <Label label="status" />
      <div>
        <Checkbox
          checked={props.currentFilter.is_new_issue}
          onChange={event =>
            props.setCurrentFilter({
              ...props.currentFilter,
              is_new_issue: event.target.checked ? true : undefined,
            })
          }
        />{' '}
        only show likely new issues
      </div>
    </>
  );
};

type TraceLengthKind = 'sources' | 'sinks';

const TraceLength = (
  props: $ReadOnly<{
    kind: TraceLengthKind,
    currentFilter: FilterDescription,
    setCurrentFilter: FilterDescription => void,
  }>,
): React$Node => {
  const value =
    props.kind === 'sources'
      ? props.currentFilter.traceLengthFromSources
      : props.currentFilter.traceLengthToSinks;
  return (
    <Row gutter={gutter}>
      <Col span={5} style={{paddingTop: 10}}>
        <Text type="secondary">
          {props.kind === 'sources' ? 'From Sources' : 'To Sinks'}
        </Text>
      </Col>
      <Col span={17}>
        <Slider
          range
          min={0}
          max={infiniteTraceLength}
          defaultValue={[0, infiniteTraceLength]}
          marks={{
            '0': '0',
            '31': 'unlimited',
          }}
          tipFormatter={value =>
            value === infiniteTraceLength ? 'unlimited' : value
          }
          value={value}
          onChange={value => {
            if (props.kind === 'sources') {
              props.setCurrentFilter({
                ...props.currentFilter,
                traceLengthFromSources: value,
              });
            } else {
              props.setCurrentFilter({
                ...props.currentFilter,
                traceLengthToSinks: value,
              });
            }
          }}
        />
      </Col>
    </Row>
  );
};

const FilterForm = (props: {
  refetch: mixed => mixed,
  refetching: boolean,
  setVisible: boolean => void,
  currentFilter: FilterDescription,
  setCurrentFilter: FilterDescription => void,
  appliedFilter: FilterDescription,
  setAppliedFilter: FilterDescription => void,
}): React$Node => {
  const apply = () => {
    props.setAppliedFilter(props.currentFilter);
    props.refetch(filterToVariables(props.currentFilter));
    props.setVisible(false);
  };

  return (
    <>
      <Codes
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Paths
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Collapse ghost>
        <Panel header="Source">
          <SourceNames
            currentFilter={props.currentFilter}
            setCurrentFilter={props.setCurrentFilter}
          />
          <SourceKinds
            currentFilter={props.currentFilter}
            setCurrentFilter={props.setCurrentFilter}
          />
        </Panel>
        <Panel header="Sink">
          <SinkNames
            currentFilter={props.currentFilter}
            setCurrentFilter={props.setCurrentFilter}
          />
          <SinkKinds
            currentFilter={props.currentFilter}
            setCurrentFilter={props.setCurrentFilter}
          />
        </Panel>
      </Collapse>
      <Statuses
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Callables
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Features
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Divider />
      <IsNewIssue
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Divider />
      <Label label="traceLengths" />
      <TraceLength
        kind="sources"
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <TraceLength
        kind="sinks"
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
      />
      <Divider />
      <div style={{textAlign: 'right'}}>
        <Button
          onClick={() => {
            props.setCurrentFilter(emptyFilter);
          }}
          disabled={filterEqual(props.currentFilter, emptyFilter)}>
          Clear
        </Button>{' '}
        <Button
          type="primary"
          onClick={apply}
          loading={props.refetching}
          disabled={filterEqual(props.currentFilter, props.appliedFilter)}>
          Apply
        </Button>
      </div>
    </>
  );
};

const SaveFilterModal = (
  props: $ReadOnly<{|
    currentFilter: FilterDescription,
    visible: boolean,
    hide: void => void,
    onSave: FilterDescription => void,
  |}>,
): React$Node => {
  const [form] = Form.useForm();

  if(props.currentFilter.name !== undefined) {
    form.setFieldsValue({
      name: props.currentFilter.name,
    });
  }

  const onCompleted = (data: any): void => {
    const filter = {
      ...data.save_filter.node,
      ...JSON.parse(data.save_filter.node.json),
    };
    props.onSave(filter);
  };
  const saveFilterMutation = gql`
    mutation SaveFilter($name: String!, $description: String, $json: String!) {
      save_filter(
        input: {name: $name, description: $description, json: $json}
      ) {
        node {
          name
          description
          json
        }
      }
    }
  `;
  const [saveFilter, {error}] = useMutation(saveFilterMutation, {onCompleted});

  if (error) {
    return <Alert type="error">{error.toString()}</Alert>;
  }

  const onOk = (): void => {
    const values = form.getFieldsValue();
    saveFilter({
      variables: {
        name: values.name,
        description: values.description,
        json: JSON.stringify(props.currentFilter),
      },
    });
    props.hide();
  };

  return (
    <Modal
      title="Save Filters..."
      visible={props.visible}
      onOk={onOk}
      okText="Save"
      onCancel={props.hide}
      zIndex={2000}>
      <Form layout="vertical" form={form} autoComplete="off">
        <Form.Item label="Name" name="name">
          <Input />
        </Form.Item>
        <Form.Item label="Description" name="description">
          <Input />
        </Form.Item>
      </Form>
    </Modal>
  );
};

export function loadFilter(): ?FilterDescription {
  const filter = window.sessionStorage.getItem('filter');
  if (filter !== undefined) {
    return JSON.parse(filter);
  }
  return null;
}

export function clearFilter(
  refetch: any = false,
  setCurrentFilter: any = false,
  currentFilter: FilterDescription = emptyFilter,
): void {
  if(!refetch) {
    window.sessionStorage.removeItem('filter');
  } else  {
    setCurrentFilter(emptyFilter);
    // workaround for https://github.com/apollographql/react-apollo/issues/3709
    // implemented in clearAndRefetch function makes us implement this hacky
    // solution. Otherwise, the app just keeps loading and does nothing.
    refetch(filterToVariables(emptyFilter));
    refetch(filterToVariables(currentFilter));
  }
}

export function filterToVariables(filter: FilterDescription): mixed {
  const rangeValue = value => {
    if (value === 0) {
      return undefined;
    }
    if (value === infiniteTraceLength) {
      return undefined;
    }
    return value;
  };

  return {
    ...filter,
    min_trace_length_to_sources: rangeValue(
      (filter.traceLengthFromSources || [])[0],
    ),
    max_trace_length_to_sources: rangeValue(
      (filter.traceLengthFromSources || [])[1],
    ),
    min_trace_length_to_sinks: rangeValue((filter.traceLengthToSinks || [])[0]),
    max_trace_length_to_sinks: rangeValue((filter.traceLengthToSinks || [])[1]),
  };
}

function getRecentFilters(): mixed {
  let data = JSON.parse(localStorage.getItem("recent_filters"));
  if(data){
    return data.recent_filters;
  }
  return [];
}

export const filtersQuery = gql`
  query Filters {
    filters {
      edges {
        node {
          name
          description
          json
        }
      }
    }
  }
`;

export const FilterControls = (props: {
  refetch: mixed => mixed,
  refetching: boolean,
}) => {
  const [search, setSearch] = useState(null);
  const initialFilter = loadFilter() || emptyFilter;
  const [saveModalVisible, setSaveModalVisible] = useState(false);
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [recentFilters, setRecentFilters] = useState(getRecentFilters())
  const [filterFormVisible, setFilterFormVisible] = useState(false);
  const [currentFilter, setCurrentFilter] = useState<FilterDescription>(
    initialFilter,
  );
  const [appliedFilter, setAppliedFilter] = useState<FilterDescription>(
    initialFilter,
  );

  useEffect(() => {
    localStorage.setItem(
      "recent_filters",
      JSON.stringify({"recent_filters": recentFilters})
    );
  });

  const {
    loading: filterLoading,
    error: filterError,
    data: filterData,
    refetch: filterRefetch
  } = useQuery(filtersQuery);

  const filters = filterLoading
    ? []
    : filterData.filters.edges.map(edge => {
        const decoded = JSON.parse(edge.node.json);
        return {
          ...edge.node,
          ...decoded,
        };
      });

  const options = filters
    .filter(filter => {
      if (search === null) {
        return true;
      }
      return (
        filter.name.toLowerCase().includes(search.toLowerCase()) ||
        filter.description?.toLowerCase()?.includes(search.toLowerCase())
      );
    })
    .map(filter => {
      return {
        value: filter.name,
        label: (
          <div>
            {filter.name}
            <br />
            <Text type="secondary">{filter.description}</Text>
          </div>
        ),
      };
    });

  var filterMap = {};
  filters.forEach(filter => (filterMap[filter.name] = filter));

  const deleteFilterMutation = gql`
    mutation DeleteFilter($name: String!) {
      delete_filter(input: {name: $name}) {
        clientMutationId
      }
    }
  `;
  const [deleteFilter, {error: deleteError}] = useMutation(
    deleteFilterMutation,
    {
      onCompleted: filterRefetch,
    },
  );

  if (deleteError) {
    return <Alert type="error">{deleteError.toString()}</Alert>;
  }
  if (filterError) {
    return <Alert type="error">{filterError.toString()}</Alert>;
  }

  const onSave = (filter: FilterDescription): void => {
    setCurrentFilter(filter);
    filterRefetch();
  };

  const onDelete = (): void => {
    deleteFilter({variables: {name: currentFilter.name}});
    setDeleteModalVisible(false);
    setCurrentFilter(emptyFilter);
    setRecentFilters(recentFilters.filter(item =>
      item !== currentFilter.name
    ));
  };

  const updateRecentFilters = (filter: string): void => {
    if(recentFilters.length > 0) {
      let filterArray = recentFilters;
      let index = filterArray.indexOf(filter);
      if(index === -1) {
        let end = filterArray.length >= 5 ? 4 : filterArray.length;
        filterArray = filterArray.slice(0, end);
        setRecentFilters([filter].concat(filterArray));
      }
    } else {
      setRecentFilters([filter]);
    }
  };

  const onSelect = (value: string): void => {
    setSearch(null);
    updateRecentFilters(value);
    setCurrentFilter(filterMap[value]);
    setAppliedFilter(filterMap[value]);
    props.refetch(filterToVariables(filterMap[value]));
    setFilterFormVisible(false);
  };

  return (
    <Sider width={300}>
      <Filter
        refetch={props.refetch}
        refetching={props.refetching}
        currentFilter={currentFilter}
        setCurrentFilter={setCurrentFilter}
        appliedFilter={appliedFilter}
        setAppliedFilter={setAppliedFilter}
        visible={filterFormVisible}
        setVisible={setFilterFormVisible}
      />
      <Modal
        visible={deleteModalVisible}
        okText="Delete"
        onOk={onDelete}
        onCancel={() => setDeleteModalVisible(false)}
        zIndex={2000}>
        Do you really want to delete{' '}
        <Text keyboard>{currentFilter.name}</Text>
      </Modal>
      <SaveFilterModal
        currentFilter={currentFilter}
        visible={saveModalVisible}
        hide={() => setSaveModalVisible(false)}
        onSave={onSave}
      />
      <Menu
        mode="inline"
        defaultOpenKeys={['recents']}
        style={{ borderRight: 0 }}
        selectable={false}>
        <>
          <AutoComplete
            style={{width: '100%', padding: '12px 12px 0 12px'}}
            options={options}
            onSelect={onSelect}
            onSearch={setSearch}
            value={search || currentFilter?.name || null}>
            <Input.Search placeholder="saved filter" />
          </AutoComplete>
        </>
        <SubMenu icon={<SettingOutlined />} title="Filter options">
          <Menu.Item
            disabled={filterEqual(emptyFilter, currentFilter)}
            onClick={() => setSaveModalVisible(true)}
            icon={<SaveOutlined />}>
            Save
          </Menu.Item>
          <Menu.Item
            disabled={currentFilter?.name === undefined}
            onClick={() => setDeleteModalVisible(true)}
            icon={<DeleteOutlined />}>
            Delete
          </Menu.Item>
          <Menu.Item
            disabled={currentFilter?.name === undefined}
            icon={<ExportOutlined />}>
            {(currentFilter?.name === undefined) ? "Export" :
              <a
                href={`/export_filter/${currentFilter.name}`}
                download={`${currentFilter.name}.json`}
                target='_blank'
                rel='noopener noreferrer'>
                Export
              </a>
            }
          </Menu.Item>
        </SubMenu>
        <SubMenu
          key="recents"
          disabled={!(recentFilters.length > 0)}
          icon={<FieldTimeOutlined />} title="Recent filters">
          { recentFilters.map(name => (
            <Menu.Item onClick={() => onSelect(name)}>
              {name}
            </Menu.Item>
          ))}
        </SubMenu>
      </Menu>
    </Sider>
  )
};

const Filter = (props: {
  refetch: any,
  refetching: boolean,
  currentFilter: FilterDescription,
  setCurrentFilter: FilterDescription => void,
  appliedFilter: FilterDescription,
  setAppliedFilter: FilterDescription => void,
}) => {
  useEffect(() => {
    window.sessionStorage.setItem('filter', JSON.stringify(props.currentFilter));
  }, [props.currentFilter]);
  const initialFilter = loadFilter() || emptyFilter;

  const content = (
    <div style={{width: '500px'}}>
      <FilterForm
        refetch={props.refetch}
        refetching={props.refetching}
        setVisible={props.setVisible}
        currentFilter={props.currentFilter}
        setCurrentFilter={props.setCurrentFilter}
        appliedFilter={props.appliedFilter}
        setAppliedFilter={props.setAppliedFilter}
      />
    </div>
  );

  const clearButton = (
    <Button
      style={{width: '100%', marginTop: '10px'}}
      icon={<ClearOutlined />}
      onClick={() =>
        clearFilter(props.refetch, props.setCurrentFilter, props.currentFilter)
      }>
        Clear Filter
    </Button>
  );

  return (
    <>
      <div style={{marginBottom: '10px'}}>
        <Popover
          visible={props.visible}
          content={content}
          placement="leftTop"
          onClick={() => props.setVisible(!props.visible)}>
          <Button
            style={{width: '100%'}}
            icon={<FilterOutlined />}
            type={!filterEqual(initialFilter, emptyFilter) ? 'primary' : null}>
            Filter...
          </Button>
        </Popover>
        { !filterEqual(initialFilter, emptyFilter) ? clearButton : null }
      </div>
    </>
  );
};

export default FilterControls;
