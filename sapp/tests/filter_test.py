# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import json
from unittest import TestCase

from ..filter import FilterValidationException, StoredFilter

filter_dictionary = {
    "name": "test filter",
    "description": "this is a description",
    "features": [
        {"mode": "all of", "features": ["first-index:name", "has:first-field"]},
        {"mode": "any of", "features": ["always-via:format-string"]},
        {
            "mode": "none of",
            "features": ["always-via:format-string", "first-index:<unknown>"],
        },
    ],
    "codes": [5005],
    "paths": ["main.py"],
    "callables": ["main.lookup", "main.listservices", "main.evaluate"],
    "traceLengthFromSources": [0, 16],
    "traceLengthToSinks": [0, 19],
    "is_new_issue": True,
}


class StoredFilterTests(TestCase):
    def _test_filter_equality(
        self,
        storedfilter_instance: StoredFilter,
        test_name: bool = True,
        test_description: bool = True,
        test_features: bool = True,
        test_codes: bool = True,
        test_paths: bool = True,
        test_callables: bool = True,
        test_traceLengthFromSources: bool = True,
        test_traceLengthToSinks: bool = True,
        test_is_new_issue: bool = True,
    ) -> None:
        if test_name:
            self.assertEqual(filter_dictionary.get("name"), storedfilter_instance.name)
            self.assertIsInstance(storedfilter_instance.name, str)

        if test_description:
            self.assertEqual(
                filter_dictionary.get("description"), storedfilter_instance.description
            )
            self.assertIsInstance(storedfilter_instance.description, str)

        if test_features:
            self.assertEqual(
                filter_dictionary.get("features"),
                storedfilter_instance.features,
            )
            self.assertIsInstance(
                storedfilter_instance.features,
                list,
            )

        if test_codes:
            self.assertEqual(
                filter_dictionary.get("codes"),
                storedfilter_instance.codes,
            )
            self.assertIsInstance(
                storedfilter_instance.codes,
                list,
            )

        if test_paths:
            self.assertEqual(
                filter_dictionary.get("paths"),
                storedfilter_instance.paths,
            )
            self.assertIsInstance(
                storedfilter_instance.paths,
                list,
            )

        if test_callables:
            self.assertEqual(
                filter_dictionary.get("callables"),
                storedfilter_instance.callables,
            )
            self.assertIsInstance(
                storedfilter_instance.callables,
                list,
            )

        if test_traceLengthFromSources:
            self.assertEqual(
                filter_dictionary.get("traceLengthFromSources"),
                storedfilter_instance.traceLengthFromSources,
            )
            self.assertIsInstance(
                storedfilter_instance.traceLengthFromSources,
                list,
            )

        if test_traceLengthToSinks:
            self.assertEqual(
                filter_dictionary.get("traceLengthToSinks"),
                storedfilter_instance.traceLengthToSinks,
            )
            self.assertIsInstance(
                storedfilter_instance.traceLengthToSinks,
                list,
            )

        if test_is_new_issue:
            self.assertEqual(
                filter_dictionary.get("is_new_issue"),
                storedfilter_instance.is_new_issue,
            )
            self.assertIsInstance(
                storedfilter_instance.is_new_issue,
                bool,
            )

    def test_instantiate_storedfilter(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        storedfilter_instance = StoredFilter(
            filter_json.pop("name"), filter_json.pop("description"), **filter_json
        )
        self._test_filter_equality(storedfilter_instance)

    def test_instantiate_storedfilter_with_kwargs(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        storedfilter_instance = StoredFilter(**filter_json)
        self._test_filter_equality(storedfilter_instance)

    def test_partial_instantiate_storedfilter(self) -> None:
        incomplete_filter_json = json.loads(json.dumps(filter_dictionary))
        incomplete_filter_json.pop("description")
        incomplete_filter_json.pop("paths")
        incomplete_filter_json.pop("callables")
        incomplete_filter_json.pop("traceLengthToSinks")
        incomplete_filter_json.pop("is_new_issue")
        partial_storedfilter_instance = StoredFilter(**incomplete_filter_json)
        self._test_filter_equality(
            partial_storedfilter_instance,
            test_description=False,
            test_paths=False,
            test_callables=False,
            test_traceLengthToSinks=False,
            test_is_new_issue=False,
        )
        self.assertEqual("", partial_storedfilter_instance.description)
        self.assertEqual([], partial_storedfilter_instance.paths)
        self.assertEqual([], partial_storedfilter_instance.callables)
        self.assertEqual(None, partial_storedfilter_instance.traceLengthToSinks)
        self.assertEqual(None, partial_storedfilter_instance.is_new_issue)

    def test_fails_instantiate_storedfilter_without_name(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        filter_json.pop("name")
        with self.assertRaises(TypeError):
            StoredFilter(**filter_json)
        with self.assertRaises(FilterValidationException):
            # pyre-ignore[6] This is intended for the test
            StoredFilter(name=None, **filter_json)

    def test_fails_instantiate_storedfilter_without_description(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        filter_json.pop("description")
        self.assertEqual("", StoredFilter(**filter_json).description)
        with self.assertRaises(FilterValidationException):
            # pyre-ignore[6] This is intended for the test
            StoredFilter(description=None, **filter_json)

    def test_fails_instantiate_storedfilter_without_filtering_conditions(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        filter_json.pop("features")
        filter_json.pop("codes")
        filter_json.pop("paths")
        filter_json.pop("callables")
        filter_json.pop("traceLengthFromSources")
        filter_json.pop("traceLengthToSinks")
        filter_json.pop("is_new_issue")
        with self.assertRaises(FilterValidationException):
            StoredFilter(**filter_json)

    def test_storedfilter_json_filtering_keys(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        self.assertEqual(
            [
                "features",
                "codes",
                "paths",
                "callables",
                "statuses",
                "source_names",
                "source_kinds",
                "sink_names",
                "sink_kinds",
                "traceLengthFromSources",
                "traceLengthToSinks",
                "is_new_issue",
            ],
            StoredFilter(**filter_json)._json_filtering_keys(),
        )

    def test_storedfilter_to_json(self) -> None:
        filter_json = json.loads(json.dumps(filter_dictionary))
        expected_json_output = json.loads(json.dumps(filter_dictionary))
        expected_json_output.pop("name")
        expected_json_output.pop("description")
        self.assertEqual(
            json.dumps(expected_json_output),
            StoredFilter(**filter_json).to_json(),
        )

    def test_partial_storedfilter_to_json(self) -> None:
        incomplete_filter_json = json.loads(json.dumps(filter_dictionary))
        incomplete_filter_json.pop("description")
        incomplete_filter_json.pop("paths")
        incomplete_filter_json.pop("callables")
        incomplete_filter_json.pop("traceLengthToSinks")
        incomplete_filter_json.pop("is_new_issue")
        expected_json_output = json.loads(json.dumps(incomplete_filter_json))
        expected_json_output.pop("name")
        self.assertEqual(
            json.dumps(expected_json_output),
            StoredFilter(**incomplete_filter_json).to_json(),
        )
