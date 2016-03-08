# DB Structure

This document describes the structure of the json database file that gets exported in `analysis` mode and gets placed in the twistd docroot when running in `measure` mode.

The structure is given here with variable keys marked as such.

    {
      "data": {
        "phantomtrain": {
          "tgen": {
            "transfers": {
              "transfer1m:1": {
                "elapsed_seconds": {
                  "checksum": 0.0,
                  "command": 0.319006,
                  "first_byte": 0.0,
                  "last_byte": 0.0,
                  "payload_progress": {
                    "0.0": 0.0
                  },
                  "proxy_choice": 0.000233,
                  "proxy_init": 0.000151,
                  "proxy_request": 0.010959,
                  "proxy_response": 0.318873,
                  "response": 0.0,
                  "socket_connect": 0.000115,
                  "socket_create": 2e-06
                },
                "endpoint_local": "localhost:127.0.0.1:45416",
                "endpoint_proxy": "localhost:127.0.0.1:27942",
                "endpoint_remote": "server1.peach-hosting.com:216.17.99.183:6666",
                "error_code": "READ",
                "filesize_bytes": 1048576,
                "hostname_local": "puntaburros.amerinoc.com",
                "hostname_remote": "(null)",
                "is_commander": true,
                "is_complete": true,
                "is_error": true,
                "is_success": false,
                "method": "GET",
                "payload_bytes_status": 0,
                "total_bytes_read": 0,
                "total_bytes_write": 50,
                "transfer_id": "transfer1m:1",
                "unix_ts_end": 1456699868.006196,
                "unix_ts_start": 1456699868.006196
              },
            },
            "transfers_summary": {
              "errors": {
                "PROXY": {
                  "1456654221": [
                    51200
                  ],
                },
                "READ": {
                  "1456618782": [
                    51200
                  ],
                },
              "time_to_first_byte": {
                "51200": {
                  "1456707932": [
                    0.36213199999999995
                  ],
                },
              },
              "time_to_last_byte": {
                "51200": {
                  "1456707932": [
                    0.6602399999999999
                  ],
                }
              }
            },
          },
          "tor": {
            "bandwidth_summary": {
              "bytes_read": {
                "1456617599": 0,
              },
              "bytes_written": {
                "1456617599": 0,
              }
            },
            "streams": {
              "23": {
                "circuit_id": "4",
                "elapsed_seconds": [
                  [
                    "USER:NEW",
                    0.0
                  ],
                  [
                    "USER:SENTCONNECT",
                    0.0
                  ],
                  [
                    "USER:REMAP",
                    0.31999993324279785
                  ],
                  [
                    "USER:SUCCEEDED",
                    0.31999993324279785
                  ],
                  [
                    "USER:CLOSED",
                    0.9800000190734863
                  ]
                ],
                "source": "127.0.0.1:48786",
                "stream_id": 23,
                "target": "216.17.99.183:6666",
                "unix_ts_end": 1456707932.67,
                "unix_ts_start": 1456707931.69
              },
            },
            "streams_summary": {
              "lifetimes": {
                "DIR_FETCH": [
                  3.950000047683716,
                ],
                "USER": [
                  114.72000002861023,
                ]
              }
            },
            "circuits": {
              "10": {
                "build_quantile": 0.8,
                "build_timeout": 1500,
                "buildtime_seconds": 1.0900001525878906,
                "circuit_id": 10,
                "elapsed_seconds": [
                  [
                    "GENERAL:LAUNCHED",
                    0.0
                  ],
                  [
                    "GENERAL:EXTENDED",
                    0.75
                  ],
                  [
                    "GENERAL:EXTENDED",
                    0.9100000858306885
                  ],
                  [
                    "GENERAL:EXTENDED",
                    1.0900001525878906
                  ],
                  [
                    "GENERAL:BUILT",
                    1.0900001525878906
                  ],
                  [
                    "GENERAL:CLOSED",
                    3601.0
                  ]
                ],
                "path": [
                  [
                    "$BB60F5BA113A0B8B44B7B37DE3567FE561E92F78~Casper04",
                    0.75
                  ],
                  [
                    "$2FD0BA57A34DC2792AF470398F72F37F9E51DC2D~serotonin",
                    0.9100000858306885
                  ],
                  [
                    "$DE7DE889E0D1A5F397AE35642060B84999581203~DigiGesTor2e3",
                    1.0900001525878906
                  ]
                ],
                "unix_ts_end": 1456711533.59,
                "unix_ts_start": 1456707932.59
              },
            },
            "circuits_summary": {
              "buildtimes": [
                1.2100000381469727,
              ],
              "lifetimes": [
                60.99000000953674,
              ],
            }
          }
        }
      }
    }


TODO the below are work-in-progress notes and should be ignored.

The constants are defined as:

  + 'type': type of database
  + 'version': version of the onionperf database
  + 'data': the onionperf analysis data
  + 'tor': data parsed from Tor sources
  + 'tgen': data parsed from TGen sources
  + 'transfers': data for each TGen transfer
  + 'transfers_summary': summary of the data for all TGen transfers
  + 'time_to_first_byte': first byte transfer timings
  + 'time_to_last_byte': last byte transfer timings
  + 'errors': contains data about transfer errors

The variables are defined as:

  + STRING1: describes the database type, should normally be 'onionperf'
  + STRING2: a nickname for the instance that collected the data in this database
  + STRING3: the error code, e.g., 'READ', 'PROXY'
  + STRING4: a unique ID for the transfer
  + INTEGER1: The size of the transfer, in bytes
  + INTEGER2: Unix timestamp that the error occurred, in seconds
  + FLOAT1: describes the database version, e.g. 1.0
  + FLOAT2: elapsed seconds of the transfer, as float; each entry represents another instance of the statistic
  + FLOAT3: size of the file that had an error at the specified time; each entry represents another instance of the error
