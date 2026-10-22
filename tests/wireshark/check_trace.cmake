# Cross-checks NR-Lite's encoders against Wireshark's independent NR RRC (ASN.1) and NAS-5GS
# dissectors: run scenarios with nrlite-sim, decode each pcap with tshark, and fail if any frame is
# malformed, raises an expert error, or if an expected message / field value is missing.
#
#   cmake -DSIM=... -DTSHARK=... -DWORKDIR=... -P check_trace.cmake

foreach(var SIM TSHARK WORKDIR)
  if(NOT DEFINED ${var})
    message(FATAL_ERROR "${var} not set")
  endif()
endforeach()

# NAS messages protected with 5G-EA0 are only decoded by Wireshark when its null_decipher
# preference is on; it must stay off for traces that use a real cipher (128-5G-EA2).
function(run_scenario name args)
  set(pcap "${WORKDIR}/wireshark_${name}.pcap")
  set(prefs -o nas-5gs.null_decipher:TRUE)
  if(args MATCHES "--nea2")
    set(prefs -o nas-5gs.null_decipher:FALSE)
  endif()
  separate_arguments(arg_list UNIX_COMMAND "${args}")
  execute_process(COMMAND ${SIM} ${arg_list} --pcap ${pcap} RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "nrlite-sim ${args} failed (${rc}): ${err}")
  endif()

  # Any malformed frame or expert error fails the check.
  execute_process(
    COMMAND ${TSHARK} -n -r ${pcap} ${prefs}
            -Y "_ws.malformed || _ws.expert.severity >= 0x800000"
            -T fields -e frame.number -e _ws.col.Info -e _ws.expert.message
    RESULT_VARIABLE rc OUTPUT_VARIABLE bad ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "tshark failed on ${pcap}: ${err}")
  endif()
  string(STRIP "${bad}" bad)
  if(NOT bad STREQUAL "")
    message(FATAL_ERROR "[${name}] Wireshark reports malformed frames:\n${bad}")
  endif()

  execute_process(
    COMMAND ${TSHARK} -n -r ${pcap} ${prefs} -V
    OUTPUT_VARIABLE detail ERROR_QUIET)
  set(${name}_DETAIL "${detail}" PARENT_SCOPE)
  message(STATUS "[${name}] ${pcap}: no malformed frames")
endfunction()

function(expect name pattern)
  if(NOT "${${name}_DETAIL}" MATCHES "${pattern}")
    message(FATAL_ERROR "[${name}] expected to find '${pattern}' in the decoded trace")
  endif()
endfunction()

run_scenario(registration "--scenario registration")
expect(registration "establishmentCause: mo-Signalling")
expect(registration "srb-Identity: 1")
expect(registration "Registration request")
expect(registration "Type of identity: SUCI")
expect(registration "MSIN: 0000000001")
expect(registration "Authentication request")
expect(registration "AMF: 8000")
expect(registration "Security mode command")
expect(registration "integrityProtAlgorithm: nia2")
expect(registration "Registration accept")
expect(registration "5G-GUTI")
expect(registration "Registration complete")
expect(registration "c1: rrcRelease")

run_scenario(deregistration "--scenario deregistration")
expect(deregistration "ng-5G-S-TMSI-Part1")
expect(deregistration "ng-5G-S-TMSI-Part2")
expect(deregistration "Deregistration request \\(UE originating\\)")
expect(deregistration "Deregistration accept \\(UE originating\\)")

run_scenario(reject "--scenario reject")
expect(reject "Registration reject")
expect(reject "Congestion")

run_scenario(multi "--scenario multi --ues 4")
expect(multi "MSIN: 0000000004")

run_scenario(nea2 "--scenario registration --nea2")
expect(nea2 "cipheringAlgorithm: nea2")
expect(nea2 "128-5G-EA2")
