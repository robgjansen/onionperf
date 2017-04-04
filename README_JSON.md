# DB Structure

This document describes the structure of the json database file that gets exported in `analysis` mode and gets placed in the twistd docroot when running in `measure` mode.

The structure is given here with variable keys marked as such.

    {
      "data": { # generic keyword
        "phantomtrain": { # nickname of the OnionPerf client, hostname if not set
          "measurement_ip" : "192.168.1.1", # public-facing IP address of the machine used for the measurements
          "tgen": { # to indicate data from TGen
            "transfers": { # the records for transfers TGen attempted
              "transfer1m:1": { # the id of a single transfer
                "elapsed_seconds": { # timing for various steps in transfer, in seconds
                  "checksum": 0.0, # step 12 if using a proxy, else step 8 (initial GET/PUT)
                  "command": 0.319006, # step 7 if using a proxy, else step 3 (initial GET/PUT)
                  "first_byte": 0.0, # step 9 if using a proxy, else step 5 (initial GET/PUT)
                  "last_byte": 0.0, # step 11 if using a proxy, else step 7 (initial GET/PUT)
                  "payload_progress": { # step 10 if using a proxy, else step 6 (initial GET/PUT)
                    "0.0": 0.0, # percent of payload completed : seconds to complete it
                    "0.1": 0.0,
                    "0.2": 0.0,
                    "0.3": 0.0,
                    "0.4": 0.0,
                    "0.5": 0.0,
                    "0.6": 0.0,
                    "0.7": 0.0,
                    "0.8": 0.0,
                    "0.9": 0.0,
                    "1.0": 0.0
                  },
                  "proxy_choice": 0.000233, # step 4 if using a proxy, else absent
                  "proxy_init": 0.000151, # step 3 if using a proxy, else absent
                  "proxy_request": 0.010959, # step 5 if using a proxy, else absent
                  "proxy_response": 0.318873, # step 6 if using a proxy, else absent
                  "response": 0.0, # step 8 if using a proxy, else step 4 (initial GET/PUT)
                  "socket_connect": 0.000115, # step 2
                  "socket_create": 2e-06 # step 1
                },
                "endpoint_local": "localhost:127.0.0.1:45416", # tgen client socket name:ip:port
                "endpoint_proxy": "localhost:127.0.0.1:27942", # proxy socket name:ip:port, if present
                "endpoint_remote": "server1.peach-hosting.com:216.17.99.183:6666", # tgen server hostname:ip:port
                "error_code": "READ", # 'NONE' or a code to indicate the type of error
                "filesize_bytes": 1048576, # size of the transfer payload
                "hostname_local": "puntaburros.amerinoc.com", # client machine hostname
                "hostname_remote": "(null)", # server machine hostname
                "is_commander": true, # true if client (initiated the transfer), else false
                "is_complete": true, # if the transfer finished, no matter the error state
                "is_error": true, # if there was an error in the transfer
                "is_success": false, # if the transfer completed and checksum passed
                "method": "GET", # transfer method (GET,PUT)
                "payload_bytes_status": 0, # cumulative number of payload bytes received
                "total_bytes_read": 0, # total bytes read from the socket
                "total_bytes_write": 50, # total written to the socket
                "transfer_id": "transfer1m:1", # the id of this transfer, unique to this run of OnionPerf
                "unix_ts_end": 1456699868.006196, # initial start time of the transfer
                "unix_ts_start": 1456699868.006196 # final end time of the transfer
              },
            },
            "transfers_summary": { # summary stats of all transfers in the 'transfers' section
              "errors": {
                "PROXY": { # PROXY type errors
                  "1456654221": [ # the second at which the error occurred
                    51200 # transfer filesizes that had errors, one entry for each error during this second
                  ],
                },
                "READ": { # READ type errors
                  "1456618782": [ # second at which the error occurred
                    51200 # transfer filesize, one for each error at this time
                  ],
                },
              "time_to_first_byte": { # time to receive the first byte of the payload
                "51200": { # file size
                  "1456707932": [ # the second at which the transfer completed
                    0.36213199999999995 # time to first byte, in seconds
                  ],
                },
              },
              "time_to_last_byte": { # time to receive the last byte of the payload
                "51200": { # file size
                  "1456707932": [ # the second at which the transfer completed
                    0.6602399999999999 # time to last byte, in seconds
                  ],
                }
              }
            },
          },
          "tor": { # indicates data from Tor
            "bandwidth_summary": { # from Tor's BW controller event
              "bytes_read": {
                "1456617599": 0, # unix time in seconds : number of bytes
              },
              "bytes_written": {
                "1456617599": 0, # unix time in seconds : number of bytes
              }
            },
            "streams": { # info about each stream
              "23": { # stream ID
                "circuit_id": "4", # circuit on which this stream was attached
                "elapsed_seconds": [ # time in seconds to reach various points, from STREAM Tor events
                  [
                    "USER:NEW", # stream purpose : stream status (from Tor)
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
                "source": "127.0.0.1:48786", # ip:port of client that created stream
                "stream_id": 23, # id of the stream used by Tor
                "target": "216.17.99.183:6666", # ip:port of the remote end of the stream
                "unix_ts_end": 1456707932.67, # unix time in seconds that the stream started
                "unix_ts_start": 1456707931.69 # unix time in seconds that the stream ended
              },
            },
            "streams_summary": { # summary stats about all streams
              "lifetimes": { # time streams were alive, in seconds
                "DIR_FETCH": [ # streams of type DIR_FETCH, one entry for each
                  3.950000047683716,
                ],
                "USER": [ # streams of type USER, one entry for each
                  114.72000002861023,
                ]
              }
            },
            "circuits": { # info about each circuit
              "10": { # circuit ID
                "build_quantile": 0.8,
                "build_timeout": 1500,
                "buildtime_seconds": 1.0900001525878906,
                "circuit_id": 10,
                "elapsed_seconds": [ # time in seconds to reach various points, from CIRC Tor events
                  [
                    "GENERAL:LAUNCHED", # circuit purpose : circuit status (from Tor)
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
                "path": [ # fingerprint~nickname for each relay in the path, seconds to extend to that relay
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
                "unix_ts_end": 1456711533.59, # unix time in seconds that the circuit started
                "unix_ts_start": 1456707932.59 # unix time in seconds that the circuit ended
              },
            },
            "circuits_summary": { # summary stats about all circuits
              "buildtimes": [ # time to build circuits in seconds, one entry for each circuit
                1.2100000381469727,
              ],
              "lifetimes": [ # lifetime of circuits in seconds, one entry for each circuit
                60.99000000953674,
              ],
            }
          }
        }
      }
    }
