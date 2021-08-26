![lint](https://github.com/facebook/sapp/workflows/lint/badge.svg)
![tests](https://github.com/facebook/sapp/workflows/tests/badge.svg)
![pyre](https://github.com/facebook/sapp/workflows/pyre/badge.svg)

# SAPP
SAPP stands for Static Analysis Post Processor. SAPP takes the raw results of Pysa and makes them explorable both through a command line interface and a web UI.

## Installation
To run SAPP, you will need [Python 3.7 or later](https://www.python.org/getit/). SAPP can be installed through [PyPI](https://pypi.org/project/fb-sapp/) with `pip install fb-sapp`.

## Getting Started
This guide assumes that you have results from a Pysa run saved in a `~/example` directory. If you are new to Pysa, you can follow [this tutorial](https://pyre-check.org/docs/pysa-quickstart/) to get started.

### Processing the Results
The postprocessing will translate the raw output containing models for every analyzed function into a format that is more suitable for exploration.

```shell
[~/example]$ sapp --database-name sapp.db analyze taint-output.json
```

After the results have been processed we can now explore them through the UI and a command line interface. We will briefly look at both of those methods here.

### Web Interface
Start the web interface with

```shell
[~/example]$ sapp --database-name sapp.db server --source-directory=<WHERE YOUR CODE LIVES>
```

and visit http://localhost:5000 in your browser (note: the URL displayed in the code output currently will not work). You will be presented with a list of issues that provide access to example traces.

### Command Line Interface
The same information can be accessed through the command line interface:

```shell
[~/example]$ sapp --database-name sapp.db explore
```

This will launch a custom IPython interface that's connected to the sqlite file.
In this mode, you can dig into the issues that Pyre surfaces. Following is an
example of how to use the various commands.

Start out by listing all known issues:
```text
==========================================================
Interactive issue exploration. Type 'help' for help.
==========================================================

[ run 1 ]
>>> issues
Issue 1
    Code: 5001
 Message: Possible shell injection Data from [UserControlled] source(s) may reach [RemoteCodeExecution] sink(s)
Callable: source.convert
 Sources: input
   Sinks: os.system
Location: source.py:9|22|32
Found 1 issues with run_id 1.
```
As expected, we have 1 issue. To select it:
```text
[ run 1 ]
>>> issue 1
Set issue to 1.

Issue 1
    Code: 5001
 Message: Possible shell injection Data from [UserControlled] source(s) may reach [RemoteCodeExecution] sink(s)
Callable: source.convert
 Sources: input
   Sinks: os.system
Location: source.py:9|22|32
```
View how the data flows from source to sink:
```text
[ run 1 > issue 1 > source.convert ]
>>> trace
     # ⎇  [callable]       [port]      [location]
     1    leaf             source      source.py:8|17|22
 --> 2    source.convert   root        source.py:9|22|32
     3    source.get_image formal(url) source.py:9|22|32
     4    leaf             sink        source.py:5|21|28
```
Move to the next callable:
```text
[ run 1 > issue 1 > source.convert ]
>>> n
     # ⎇  [callable]       [port]      [location]
     1    leaf             source      source.py:8|17|22
     2    source.convert   root        source.py:9|22|32
 --> 3    source.get_image formal(url) source.py:9|22|32
     4    leaf             sink        source.py:5|21|28
```
Show the source code at that callable:
```text
[ run 1 > issue 1 > source.get_image ]
>>> list
In source.convert [source.py:9|22|32]
     4      command = "wget -q https:{}".format(url)
     5      return os.system(command)
     6
     7  def convert() -> None:
     8      image_link = input("image link: ")
 --> 9      image = get_image(image_link)
                              ^^^^^^^^^^
```
Move to the next callable and show source code:
```text
[ run 1 > issue 1 > source.get_image ]
>>> n
     # ⎇  [callable]       [port]      [location]
     1    leaf             source      source.py:8|17|22
     2    source.convert   root        source.py:9|22|32
     3    source.get_image formal(url) source.py:9|22|32
 --> 4    leaf             sink        source.py:5|21|28

[ run 1 > issue 1 > leaf ]
>>> list
In source.get_image [source.py:5|21|28]
     1  import os
     2
     3  def get_image(url: str) -> int:
     4      command = "wget -q https:{}".format(url)
 --> 5      return os.system(command)
                             ^^^^^^^
     6
     7  def convert() -> None:
     8      image_link = input("image link: ")
     9      image = get_image(image_link)
```
Jump to the first callable and show source code:
```text
[ run 1 > issue 1 > leaf ]
>>> jump 1
     # ⎇  [callable]       [port]      [location]
 --> 1    leaf             source      source.py:8|17|22
     2    source.convert   root        source.py:9|22|32
     3    source.get_image formal(url) source.py:9|22|32
     4    leaf             sink        source.py:5|21|28

[ run 1 > issue 1 > leaf ]
>>> list
In source.convert [source.py:8|17|22]
     3  def get_image(url: str) -> int:
     4      command = "wget -q https:{}".format(url)
     5      return os.system(command)
     6
     7  def convert() -> None:
 --> 8      image_link = input("image link: ")
                         ^^^^^
     9      image = get_image(image_link)
```

You can refer to the `help` command to get more information about available commands in the command line interface.

## Terminology
A single SAPP database can keep track of more than just a single run. This opens up the possibility of reasoning about *newly introduced issues* in a codebase.

Every invocation of
```shell
[~/example]$ sapp --database-name sapp.db analyze taint-output.json
```
will add a single *run* to the database. An *issue* can exist over multiple runs (we typically call the issue in a single run an *instance*). You can select a run from the web UI and look at all the instances of that run. You can also chose to only show the instances of issues that are newly introduced in this run in the filter menu.

Each instance consists of a *data flow* from a particular source kind (e.g. user controlled input) into a *callable* (i.e. a function or method), and a data flow from that callable into a particular sink kind (e.g. RCE).

*Note: the data can come from different sources of the same kind and flow into different sinks of the same kind. The traces view of a single instance represents a multitude of traces, not just a single trace.*

## Filters
SAPP filters are used to include/exclude which issues are shown to you by the issue properties you choose. Filters are useful to remove noise from the output from your static analysis tool, so you can focus on the particular properties of issues you care about.

SAPP functionality can be accessed through the web interface or through a subcommand of `sapp filter`.

### File Format
A filter is required to have a `name` and at least one other key, excluding `description`. Filters can be stored as JSON in the following format:
```json
{
    "name": "Name of filter",
    "description": "Description for the filter",
    "features": [
        {
            "mode": "all of",
            "features": [
                "via:feature1",
                "feature2",
            ]
        },
        {
            "mode": "any of",
            "features": [
                "always-via:feature3",
            ]
        },
        {
            "mode": "none of",
            "features": [
                "type:feature5",
            ]
        }
    ],
    "codes": [
        5005
    ],
    "paths": [
        "filename.py"
    ],
    "callables": [
        "main.function_name",
    ],
    "traceLengthFromSources": [
        0,
        3
    ],
    "traceLengthToSinks": [
        0,
        5
    ],
    "is_new_issue": false
}
```

You can find some example filters to reference in the [pyre-check repo](https://github.com/facebook/pyre-check/tree/main/tools/sapp/pysa_filters)

### Importing filters
You can import a filter from a file by running:
```shell
[~/example]$ sapp --database-name sapp.db filter import filter-filename.json
```

You can also import all filters within a directory by running:
```shell
[~/example]$ sapp --database-name sapp.db filter import path/to/list_of_filters
```

### Exporting filters
You can view a filter in a SAPP DB by running:
```
[~/example]$ sapp --database-name sapp.db filter export "filter name"
```

You can export a filter from a SAPP DB to a file by running:
```
[~/example]$ sapp --database-name sapp.db filter export "filter name" --output-path /path/to/filename.json
```

### Deleting filters
You can delete filters by name with:
```shell
[~/example]$ sapp --database-name sapp.db filter delete "filter name 1" "filter name 2" "filter name 3"
```

### Filtering list of issues
You can apply a filter to a list of issues by run number. For example, the following command will show you a list of issues after applying `example-filter` to run `1`:
```shell
[~/example]$ sapp --database-name sapp.db filter issues 1 example-filter.json
```

You can also apply a list of filters to a single list of issues by run number. SAPP will apply each filter individually from the directory you specify to the list of issues and merge results into a single list of issues to show you. For example, the following command will show you a list of issues after applying every filter in `list_of_filters` to run `1`:
```shell
[~/example]$ sapp --database-name sapp.db filter issues 1 path/to/list_of_filters
```

#### SARIF Output
You can get the output of a filtered run in [SARIF](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#about-sarif-support) by first storing warning codes information from the static analysis tool in SAPP:
```shell
sapp --database-name sapp.db update warning-codes taint-metadata.json
```

Then running `sapp filter issues` with `--output-format=sarif`:
```shell
sapp --database-name sapp.db filter issues 1 path/to/list_of_filters --output-format sarif
```

## Development Environment Setup
Start by cloning the repo and setting up a virtual environment:
```shell
$ git clone git@github.com:facebook/sapp.git && cd sapp
$ python3 -m venv ~/.venvs/sapp
$ source ~/.venvs/sapp/bin/activate
(sapp) $ pip3 install -r requirements.txt
```

Run the flask server in debug mode:
```shell
(sapp) $ python3 -m sapp.cli server --debug
```

Parse static analysis output and save to disk:
```shell
(sapp) $ python3 -m sapp.cli analyze taint-output.json
```

Installing dependencies for frontend:
```shell
(sapp) $ cd sapp/ui/frontend && npm install
```

To run SAPP with hot reloading of the Web UI, you need have the frontend and backend running simultaneously. In a production environment, the frontend application is compiled and served directly by the backend exposed on port 5000. But in a development environment, the frontend runs in port 3000 and the backend runs in port 5000. You can indicate to SAPP to run in the development environment with the `debug` flag

Run the flask server and react app in development mode:
```shell
(sapp) $ python3 -m sapp.cli server --debug
(sapp) $ cd sapp/ui/frontend && npm run-script start
```
Then visit `http://localhost:3000`

## FAQ
### Why is SAPP it's own project and not just part of Pysa?
Stay tuned for future announcements.

## License

SAPP is licensed under the MIT license.
