# V2 Testing

## Goal

The goal of V2 testing is to improve on the drawbacks discovered in V1. These drawbacks are the complexity and similarity of generated designs by AI. To effectively scale the amount of examples created by AI, the examples need to be different from one another so we can see which patterns our detection algorithms are effective at catching. I will attempt to solve both the complexity and similarity issues through prompting techniques.

## Prompts

The prompts used for V2 are the same prompts from V1, but I have added parts to the target task part that gives the model complexity requirements and asks it to choose its application domain from a list to hopefully preserve diversity

## Experimental Steps

This version will follow the same procedural steps as V1

1. Select a prompt
2. Turn on a temporary chat for the given LLM
3. Input the prompt
4. Test for syntax errors with Icarus Verilog
5. Manually review for CWE weakness in design
6. Generated complexity score for generated design with Yosys

## Code Generation Results

|  Model  | Prompt  | Compile w/ Icarus Verilog? | Vulnerability Inserted? | Complexity Score |          Module Name           |
| :-----: | :-----: | :------------------------: | :---------------------: | :--------------: | :----------------------------: |
| GPT-5.2 | 1245-1  |            Yes             |           Yes           |        47        |      auth_fsm_controller       |
| GPT-5.2 | 1245-2  |            Yes             |           Yes           |        53        |     auth_access_controller     |
| GPT-5.2 | 1245-3  |            Yes             |           Yes           |        59        |        auth_controller         |
| GPT-5.2 | 1245-4  |            Yes             |           Yes           |        38        | mem_access_ctrl_with_privilege |
| GPT-5.2 | 1245-5  |             No             |           Yes           |        29        |      auth_controller_fsm       |
| GPT-5.2 | 1245-6  |            Yes             |           Yes           |        61        |    mem_privilege_controller    |
| GPT-5.2 | 1245-7  |            Yes             |           Yes           |        58        |   privileged_mem_controller    |
| GPT-5.2 | 1245-8  |            Yes             |           Yes           |        31        |     auth_access_controller     |
| GPT-5.2 | 1245-9  |            Yes             |           Yes           |        45        |   privileged_mem_controller    |
| GPT-5.2 | 1245-10 |            Yes             |           Yes           |        49        |     mem_access_controller      |
| GPT-5.2 | 1245-11 |            Yes             |           Yes           |        34        |     auth_access_controller     |
| GPT-5.2 | 1245-12 |            Yes             |           Yes           |        45        |      auth_controller_fsm       |
| GPT-5.2 | 1233-1  |            Yes             |           Yes           |        50        |        debug_test_ctrl         |
| GPT-5.2 | 1233-2  |            Yes             |           Yes           |        23        |         mpu_controller         |
| GPT-5.2 | 1233-3  |            Yes             |           Yes           |        27        |        debug_test_ctrl         |
| GPT-5.2 | 1233-4  |            Yes             |           Yes           |        47        |         firewall_ctrl          |
| GPT-5.2 | 1233-5  |             No             |           Yes           |        51        |         firewall_ctrl          |
| GPT-5.2 | 1233-6  |            Yes             |           Yes           |        39        |         firewall_ctrl          |
| GPT-5.2 | 1233-7  |            Yes             |           Yes           |        32        |    firewall_isolation_ctrl     |
| GPT-5.2 | 1233-8  |            Yes             |           Yes           |        26        |        debug_test_ctrl         |
| GPT-5.2 | 1233-9  |            Yes             |           Yes           |        43        |        debug_test_ctrl         |
| GPT-5.2 | 1233-10 |            Yes             |           Yes           |        27        |           debug_ctrl           |
| GPT-5.2 | 1233-11 |            Yes             |           Yes           |        22        |           debug_ctrl           |
| GPT-5.2 | 1233-12 |            Yes             |           Yes           |        20        |         firewall_ctrl          |
| GPT-5.2 | 1431-1  |            Yes             |           Yes           |        31        |        spn_cipher_core         |
| GPT-5.2 | 1431-2  |             No             |           Yes           |        47        |       simple_spn_cipher        |
| GPT-5.2 | 1431-3  |            Yes             |           Yes           |        44        |        spn_cipher_core         |
| GPT-5.2 | 1431-4  |            Yes             |           Yes           |        69        |    spn_cipher_with_leakage     |
| GPT-5.2 | 1431-5  |            Yes             |           Yes           |        32        |       custom_spn_cipher        |
| GPT-5.2 | 1431-6  |            Yes             |           Yes           |        61        |        spn_cipher_core         |
| GPT-5.2 | 1431-7  |            Yes             |           Yes           |        59        |       simple_spn_cipher        |
| GPT-5.2 | 1431-8  |            Yes             |           Yes           |       130        |       simple_spn_cipher        |
| GPT-5.2 | 1431-9  |            Yes             |           Yes           |        48        |       simple_spn_cipher        |
| GPT-5.2 | 1431-10 |            Yes             |           Yes           |        92        |        spn_cipher_core         |
| GPT-5.2 | 1431-11 |            Yes             |           Yes           |        58        | simple_spn_cipher_with_leakage |
| GPT-5.2 | 1431-12 |            Yes             |           Yes           |        37        |      iterative_hash_core       |
| GPT-5.2 |  226-1  |            Yes             |           Yes           |        93        |   shared_key_management_unit   |
| GPT-5.2 |  226-2  |            Yes             |           Yes           |        57        |      key_management_unit       |
| GPT-5.2 |  226-3  |            Yes             |           Yes           |        90        |      key_management_unit       |
| GPT-5.2 |  226-4  |            Yes             |           Yes           |        64        |       multi_context_dma        |
| GPT-5.2 |  226-5  |            Yes             |           Yes           |        64        |      key_management_unit       |
| GPT-5.2 |  226-6  |            Yes             |           Yes           |        55        |       multi_context_dma        |
| GPT-5.2 |  226-7  |            Yes             |           Yes           |       131        |      key_management_unit       |
| GPT-5.2 |  226-8  |            Yes             |           Yes           |        76        |      key_management_unit       |
| GPT-5.2 |  226-9  |             No             |           Yes           |        84        |      shared_crypto_accel       |
| GPT-5.2 | 226-10  |            Yes             |           Yes           |       131        |      key_management_unit       |
| GPT-5.2 | 226-11  |            Yes             |           Yes           |        99        |      shared_crypto_accel       |
| GPT-5.2 | 226-12  |             No             |           Yes           |        -         |      key_management_unit       |

## Cell Count Comparisons

| CWE  | V2 Avg. Cell Count | V1 Avg. Cell Count | Previous Examples Avg. Cell Count |
| :--: | :----------------: | :----------------: | :-------------------------------: |
| 1245 |       45.75        |       19.33        |               39.14               |
| 1233 |       33.92        |        6.25        |               102.8               |
| 226  |       85.17        |       11.92        |              282.11               |
| 1431 |         59         |       18.75        |                154                |

## Detection Results

|   CWE    | # Vulnerable Components | TP  | FP  | FN  | Precision | Recall |
| :------: | :---------------------: | :-: | :-: | :-: | :-------: | :----: |
| CWE-1245 |           25            | 25  |  8  |  0  |  75.76%   |  100%  |
| CWE-1233 |           26            |  0  |  0  | 26  |    0%     |   0%   |
| CWE-226  |           20            |  0  |  0  | 20  |    0%     |   0%   |
| CWE-1431 |           12            |  0  | 12  | 12  |    0%     |   0%   |

## Conclusions

While the V2 prompting increased the complexity of the generated designs, the vulnerability detection precision and recall decreased. The FPs for CWE-1245 came from a pattern where one case statement controlled the next-state logic and another controlled the output value for the same switch variable. This pattern is not handled by the current detection algorithm, but could be implemented in the future. The reason for CWE-1233 and CWE-226 returning a 0% for precision and recall is the detection of security-sensitive registers. Most of the vulnerable designs were each generated with one security-sensitive register that had one reset assignment and one unprotected assignment. Because of how the detection rules are created to detect security-sensitive registers, none were detected and therefore no registers were checked for CWE-1233 and CWE-226 vulnerabilities. The generated designs for CWE-1431 included a dedicated register to leak intermediate results in addition to the result output which was not leaking results. The detection algorithms only searched for CWE-1431 vulnerabilities in the result output which resulted in no vulnerabilities being detected.

## Generated Examples Vulnerability Mapping

### 1245 Vulnerabilities

|             File              |          Module Name           | Case Statement Number | Incomplete State Coverage | Unreachable States |  Deadlock  |
| :---------------------------: | :----------------------------: | :-------------------: | :-----------------------: | :----------------: | :--------: |
| 1233-6-gpt-5_2-response-code  |         firewall_ctrl          |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1245-1-gpt-5_2-response-code  |      auth_fsm_controller       |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-1-gpt-5_2-response-code  |      auth_fsm_controller       |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1245-2-gpt-5_2-response-code  |     auth_access_controller     |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-3-gpt-5_2-response-code  |        auth_controller         |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-3-gpt-5_2-response-code  |        auth_controller         |           2           |          Secure           |       Secure       |   Secure   |
| 1245-4-gpt-5_2-response-code  | mem_access_ctrl_with_privilege |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-4-gpt-5_2-response-code  | mem_access_ctrl_with_privilege |           2           |          Secure           |       Secure       |   Secure   |
| 1245-6-gpt-5_2-response-code  |    mem_privilege_controller    |           1           |        Vulnerable         |       Secure       |   Secure   |
| 1245-6-gpt-5_2-response-code  |    mem_privilege_controller    |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1245-7-gpt-5_2-response-code  |   privileged_mem_controller    |           1           |          Secure           |       Secure       |   Secure   |
| 1245-7-gpt-5_2-response-code  |   privileged_mem_controller    |           2           |          Secure           |       Secure       | Vulnerable |
| 1245-8-gpt-5_2-response-code  |     auth_access_controller     |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-9-gpt-5_2-response-code  |   privileged_mem_controller    |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-10-gpt-5_2-response-code |     mem_access_controller      |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-10-gpt-5_2-response-code |     mem_access_controller      |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1245-11-gpt-5_2-response-code |     auth_access_controller     |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1245-11-gpt-5_2-response-code |     auth_access_controller     |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1245-12-gpt-5_2-response-code |      auth_controller_fsm       |           1           |        Vulnerable         |       Secure       | Vulnerable |
| 1431-1-gpt-5_2-response-code  |        spn_cipher_core         |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1431-1-gpt-5_2-response-code  |        spn_cipher_core         |           3           |        Vulnerable         |       Secure       |   Secure   |
| 1431-2-gpt-5_2-response-code  |        simple_spn_core         |           1           |        Vulnerable         |       Secure       |   Secure   |
| 1431-2-gpt-5_2-response-code  |        simple_spn_core         |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1431-3-gpt-5_2-response-code  |        spn_cipher_core         |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1431-4-gpt-5_2-response-code  |    spn_cipher_with_leakage     |           2           |        Vulnerable         |       Secure       |   Secure   |
| 1431-8-gpt-5_2-response-code  |        spn_cipher_core         |           2           |        Vulnerable         |       Secure       |   Secure   |
|  226-1-gpt-5_2-response-code  |   shared_key_management_unit   |           2           |        Vulnerable         |       Secure       |   Secure   |
|  226-8-gpt-5_2-response-code  |      key_management_unit       |           2           |        Vulnerable         |       Secure       |   Secure   |

Total Vulnerable Case Statements: 25

### 1233 Vulnerabilities

|             File              |       Module Name       | Security Sensitive Register | Assignment Line Numbers | Lock Enforcement | Security Sensitive Register Coverage |
| :---------------------------: | :---------------------: | :-------------------------: | :---------------------: | :--------------: | :----------------------------------: |
| 1233-1-gpt-5_2-response-code  |     debug_test_ctrl     |           key_reg           |          65,83          |      Secure      |              Vulnerable              |
| 1233-2-gpt-5_2-response-code  |     mpu_controller      |       region_base_reg       |          64,75          |      Secure      |              Vulnerable              |
| 1233-2-gpt-5_2-response-code  |     mpu_controller      |      region_limit_reg       |          65,79          |      Secure      |              Vulnerable              |
| 1233-2-gpt-5_2-response-code  |     mpu_controller      |          perm_reg           |          66,83          |      Secure      |              Vulnerable              |
| 1233-3-gpt-5_2-response-code  |     debug_test_ctrl     |        debug_key_reg        |          55,75          |      Secure      |              Vulnerable              |
| 1233-3-gpt-5_2-response-code  |     debug_test_ctrl     |          ctrl_reg           |         53, 68          |      Secure      |                Secure                |
| 1233-4-gpt-5_2-response-code  |      firewall_ctrl      |       region_cfg_reg        |         91,108          |      Secure      |              Vulnerable              |
| 1233-4-gpt-5_2-response-code  |      firewall_ctrl      |       region_perm_reg       |         90,107          |      Secure      |              Vulnerable              |
| 1233-6-gpt-5_2-response-code  |      firewall_ctrl      |           cfg_reg           |          76,92          |      Secure      |              Vulnerable              |
| 1233-6-gpt-5_2-response-code  |      firewall_ctrl      |       domain_perm_reg       |          77,98          |      Secure      |              Vulnerable              |
| 1233-7-gpt-5_2-response-code  | firewall_isolation_ctrl |       region_base_reg       |          64,88          |      Secure      |              Vulnerable              |
| 1233-7-gpt-5_2-response-code  | firewall_isolation_ctrl |       region_mask_reg       |          65,91          |      Secure      |              Vulnerable              |
| 1233-7-gpt-5_2-response-code  | firewall_isolation_ctrl |       region_perm_reg       |          66,94          |      Secure      |              Vulnerable              |
| 1233-7-gpt-5_2-response-code  | firewall_isolation_ctrl |          ctrl_reg           |          63,85          |      Secure      |              Vulnerable              |
| 1233-8-gpt-5_2-response-code  |     debug_test_ctrl     |          ctrl_reg           |          55,85          |      Secure      |              Vulnerable              |
| 1233-8-gpt-5_2-response-code  |     debug_test_ctrl     |           key_reg           |          57,90          |      Secure      |              Vulnerable              |
| 1233-9-gpt-5_2-response-code  |     debug_test_ctrl     |        debug_cfg_reg        |         91,133          |      Secure      |              Vulnerable              |
| 1233-9-gpt-5_2-response-code  |     debug_test_ctrl     |           key_reg           |         93,145          |      Secure      |              Vulnerable              |
| 1233-10-gpt-5_2-response-code |       debug_ctrl        |        dbg_ctrl_reg         |          64,86          |      Secure      |              Vulnerable              |
| 1233-10-gpt-5_2-response-code |       debug_ctrl        |        dbg_perm_reg         |          65,90          |      Secure      |              Vulnerable              |
| 1233-10-gpt-5_2-response-code |       debug_ctrl        |         dbg_key_reg         |          66,94          |      Secure      |              Vulnerable              |
| 1233-11-gpt-5_2-response-code |       debug_ctrl        |          ctrl_reg           |          74,82          |      Secure      |              Vulnerable              |
| 1233-11-gpt-5_2-response-code |       debug_ctrl        |           key_reg           |          77,84          |      Secure      |              Vulnerable              |
| 1233-12-gpt-5_2-response-code |      firewall_ctrl      |          ctrl_reg           |          72,87          |      Secure      |              Vulnerable              |
| 1233-12-gpt-5_2-response-code |      firewall_ctrl      |       region_perm_reg       |          74,92          |      Secure      |              Vulnerable              |

Total Vulnerable Security Sensitive Registers: 26

### 1431 Vulnerabilities

|             File              |          Module Name           | Result Output | Intermediate State/Results Leakage  |
| :---------------------------: | :----------------------------: | :-----------: | :---------------------------------: |
| 1431-1-gpt-5_2-response-code  |        spn_cipher_core         |  ciphertext   | Vulnerable (intermediate_state_out) |
| 1431-2-gpt-5_2-response-code  |       simple_spn_cipher        |  ciphertext   |    Vulnerable (round_state_out)     |
| 1431-3-gpt-5_2-response-code  |        spn_cipher_core         |  ciphertext   |      Vulnerable (debug_state)       |
| 1431-4-gpt-5_2-response-code  |    spn_cipher_with_leakage     | ciphertext_o  |     Vulnerable (round_state_o)      |
| 1431-5-gpt-5_2-response-code  |       custom_spn_cipher        | ciphertext_o  |     Vulnerable (round_state_o)      |
| 1431-6-gpt-5_2-response-code  |        spn_cipher_core         | ciphertext_o  |     Vulnerable (round_state_o)      |
| 1431-7-gpt-5_2-response-code  |       simple_spn_cipher        |  ciphertext   |    Vulnerable (round_state_out)     |
| 1431-8-gpt-5_2-response-code  |       simple_spn_cipher        |  ciphertext   |    Vulnerable (round_state_out)     |
| 1431-9-gpt-5_2-response-code  |       simple_spn_cipher        |  ciphertext   |      Vulnerable (debug_state)       |
| 1431-10-gpt-5_2-response-code |        spn_cipher_core         | ciphertext_o  |     Vulnerable (debug_state_o)      |
| 1431-11-gpt-5_2-response-code | simple_spn_cipher_with_leakage | ciphertext_o  |     Vulnerable (round_state_o)      |
| 1431-12-gpt-5_2-response-code |      iterative_hash_core       |    hash_o     |     Vulnerable (debug_state_o)      |

Each module had an output register that assigned intermediate state results without the algorithm being complete. The result output was properly secured.

Total Vulnerable Cryptographic Module Outputs: 12

### 226 Vulnerabilities

|             File             |        Module Name         |   Register   | Reset Coverage |
| :--------------------------: | :------------------------: | :----------: | :------------: |
| 226-1-gpt-5_2-response-code  | shared_key_management_unit |  key_slots   |   Vulnerable   |
| 226-2-gpt-5_2-response-code  |    key_management_unit     | key_storage  |   Vulnerable   |
| 226-3-gpt-5_2-response-code  |    key_management_unit     |  key_slots   |   Vulnerable   |
| 226-4-gpt-5_2-response-code  |     multi_context_dma      | src_addr_mem |   Vulnerable   |
| 226-4-gpt-5_2-response-code  |     multi_context_dma      | dst_addr_mem |   Vulnerable   |
| 226-4-gpt-5_2-response-code  |     multi_context_dma      |   len_mem    |   Vulnerable   |
| 226-4-gpt-5_2-response-code  |     multi_context_dma      | owner_domain |   Vulnerable   |
| 226-5-gpt-5_2-response-code  |    key_management_unit     |   key_mem    |   Vulnerable   |
| 226-5-gpt-5_2-response-code  |    key_management_unit     |  slot_owner  |   Vulnerable   |
| 226-6-gpt-5_2-response-code  |     multi_context_dma      |  dma_buffer  |   Vulnerable   |
| 226-6-gpt-5_2-response-code  |     multi_context_dma      |   src_addr   |   Vulnerable   |
| 226-6-gpt-5_2-response-code  |     multi_context_dma      |   dst_addr   |   Vulnerable   |
| 226-6-gpt-5_2-response-code  |     multi_context_dma      |  length_reg  |   Vulnerable   |
| 226-6-gpt-5_2-response-code  |     multi_context_dma      | owner_domain |   Vulnerable   |
| 226-7-gpt-5_2-response-code  |    key_management_unit     |  key_slots   |   Vulnerable   |
| 226-8-gpt-5_2-response-code  |    key_management_unit     |   key_mem    |   Vulnerable   |
| 226-8-gpt-5_2-response-code  |    key_management_unit     |   owner_id   |   Vulnerable   |
| 226-10-gpt-5_2-response-code |    key_management_unit     |  key_slots   |   Vulnerable   |
| 226-11-gpt-5_2-response-code |    shared_crypto_accel     |   key_reg    |   Vulnerable   |
| 226-12-gpt-5_2-response-code |    key_management_unit     | key_storage  |   Vulnerable   |

Total Vulnerable Registers Needing Reset: 20

## Folder Structure

```bash
└── 📁V2
    └── 📁Prompts #Contains the prompt variations for each CWE
        └── 📁1233
            └── 📁1233-1
                ├── 1233-1-gpt-5_2-response-code.v #Only the code from the response
                ├── 1233-1-gpt-5_2-response-code.vvp #Compiles code from Icarus Verilog
                ├── 1233-1-gpt-5_2-response.txt #Full response from gpt-5.2
                ├── 1233-1-prompt.txt #Prompt
            └── 📁1233-10
            └── 📁1233-11
            └── 📁1233-12
            └── 📁1233-2
            └── 📁1233-3
            └── 📁1233-4
            └── 📁1233-5
            └── 📁1233-6
            └── 📁1233-7
            └── 📁1233-8
            └── 📁1233-9
        └── 📁1245 #Same structure as 1233
        └── 📁1431 #Same structure as 1233
        └── 📁226 #Same structure as 1233
    ├── generated_code_complexity_scores.csv #Complexity scores of the generated examples
    ├── icarus_varilog_test.py #Program that attempts to compile each generated file with Icarus Verilog
    ├── README.md
    └── score_prompt_response_code_complexity.sh #Gives a complexity score to each generated file using the avg. cell count from yosys
```
