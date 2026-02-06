/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @format
 */

const js = require('@eslint/js');
const globals = require('globals');
const babelParser = require('@babel/eslint-parser');
const reactPlugin = require('eslint-plugin-react');

// Flow type globals that are used in the codebase
const flowGlobals = {
  $ReadOnly: 'readonly',
  $ReadOnlyArray: 'readonly',
  $ReadOnlyList: 'readonly',
  $NonMaybeType: 'readonly',
  $Keys: 'readonly',
  $Values: 'readonly',
  $Diff: 'readonly',
  $Shape: 'readonly',
  $PropertyType: 'readonly',
  $ElementType: 'readonly',
  $Call: 'readonly',
  $ObjMap: 'readonly',
  React$Node: 'readonly',
  React$Element: 'readonly',
  React$ComponentType: 'readonly',
  React$AbstractComponent: 'readonly',
  React$MixedElement: 'readonly',
  SyntheticEvent: 'readonly',
  SyntheticInputEvent: 'readonly',
  SyntheticMouseEvent: 'readonly',
  SyntheticKeyboardEvent: 'readonly',
};

module.exports = [
  {
    ignores: [
      '**/node_modules/**',
      '**/build/**',
      '**/coverage/**',
      '**/config/**',
      'eslint.config.js',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'src/**/*.jsx'],
    plugins: {
      react: reactPlugin,
    },
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          babelrc: false,
          configFile: false,
          presets: ['@babel/preset-react', '@babel/preset-flow'],
        },
        ecmaFeatures: {
          jsx: true,
        },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.jest,
        ...flowGlobals,
      },
    },
    settings: {
      react: {
        version: 'detect',
      },
    },
    rules: {
      // Disable no-unused-vars for JSX components that ESLint can't detect usage for
      'no-unused-vars': 'off',
      // Use react/jsx-uses-react and react/jsx-uses-vars instead for JSX
      'react/jsx-uses-react': 'error',
      'react/jsx-uses-vars': 'error',
      // Disable extra boolean cast warning since some are intentional
      'no-extra-boolean-cast': 'off',
    },
  },
];
