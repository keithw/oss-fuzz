# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module for outputting SARIF data."""
import copy
import os
import json

from clusterfuzz import stacktraces


BUG_ID = 'bug'
# RULES = [
#   {
#       'id': '1',  # Needs to be a stable, opaque identifier.
#       'name': BUG_ID,
#       'shortDescription': {
#         'text': 'A bug'
#       },
#       'fullDescription': {
#         'text': 'A bug'
#       },
#       'help': {
#         'text': 'A bug'
#       }
#   }
# ]

RULES = {
  'version': '2.1.0',
  '$schema': 'http://json.schemastore.org/sarif-2.1.0-rtm.4',
  'runs': [
    {
      'tool': {
        'driver': {
          'name': 'ClusterFuzzLite/CIFuzz',
          'informationUri': 'https://google.github.io/clusterfuzzlite/',
          'rules': [
            {
              'id': 'no-crashes',
              'shortDescription': {
                'text': 'don\'t crash'
              },
              'helpUri': 'https://eslint.org/docs/rules/no-unused-vars',
              'properties': {
                'category': 'Crashes'
              }
            }
          ]
        }
      },
      'artifacts': [
        {
          'location': {
            'uri': 'file:///C:/dev/sarif/sarif-tutorials/samples/Introduction/simple-example.js'
          }
        }
      ],
      'results': [
      ]
    }
  ]
}

SRC_ROOT = '/src/'

def redact_src_path(src_path):
  if src_path.startswith(SRC_ROOT):
    src_path = src_path[len(SRC_ROOT):]

  src_path = os.sep.join(src_path.split(os.sep)[1:])
  return src_path


def get_frame(crash_info):
  if not crash_info.crash_state:
    return
  state = crash_info.crash_state.split('\n')[0]

  print('state', state, crash_info.crash_state)
  for crash_frames in crash_info.frames:
    for frame in crash_frames:
      if frame.function_name.startswith(state): # !!! buggy
        return frame
  return None


def get_frame_info(crash_info):
  frame = get_frame(crash_info)
  if not frame:
    return (None, 1)
  print(frame.filename, int(frame.fileline or 1))
  return frame.filename, int(frame.fileline or 1)

def get_sarif_data(stacktrace, target_path):
  fuzz_target = os.path.basename(target_path)
  stack_parser = stacktraces.StackParser(fuzz_target=fuzz_target,
                                         symbolized=True,
                                         detect_ooms_and_hangs=True,
                                         include_ubsan=True)
  crash_info = stack_parser.parse(stacktrace)
  frame_info = get_frame_info(crash_info)
  print('frameinfo', frame_info, crash_info.frames[0][0], crash_info.frames)
  uri = redact_src_path(frame_info[0])

  result = {
      'level': 'error',
      'message': {
          'text': crash_info.crash_type
      },
      'locations': [
          {
              'physicalLocation': {
                  'artifactLocation': {
                      'uri': uri,
                      'index': 0
                  },
                  'region': {
                      'startLine': frame_info[1],
                      'startColumn': 1,
                  }
              }
          }
      ],
      'ruleId': 'no-crashes',
      'ruleIndex': 0
  }
  data = copy.deepcopy(RULES)
  data['runs'][0]['results'].append(result)
  return data


def write_stacktrace_to_sarif(stacktrace, target_path, workspace):
  data = get_sarif_data(stacktrace, target_path)
  workspace.initialize_dir(workspace.sarif)
  with open(os.path.join(workspace.sarif, 'results.sarif'), 'w') as file_handle:
    file_handle.write(json.dumps(data))
