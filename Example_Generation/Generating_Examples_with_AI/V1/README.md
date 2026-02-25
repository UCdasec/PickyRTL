# V1 Testing

## Goal

Use AI to generate a large dataset that can be used to comprehensively evaluate CWE detection algorithms. This first version of generating examples used the free version of ChatGPT to serve as a proof of concept and whether it was possible.

## Prompts

12 prompts were created for each CWE that were made up of combined prompt parts.

Constant Prompt Parts

- Target Task - Told the LLM to generate an HDL file with a weakness for a given CWE
- CWE Description - Description of the given CWE

Variable Prompt Parts

- Self-scrutiny - Prompted the model to review its answer before giving its response
- Examples - Gave the model a 'secure' example and a 'vulnerable' example for the specific CWE
- Temperature Simulation - Attempted to simulate the LLM temperature variable to get more creative or less creative responses

This table shows the prompt variable matrix with an ID for each prompt

| Prompt-id | Target CWE |            Target Task             | Self-scrutiny |   Examples   | Temperature Simulation |
| :-------: | :--------: | :--------------------------------: | :-----------: | :----------: | :--------------------: |
|  1245-1   |  CWE-1245  | Generate design with vulnerability |   Included    | Not Included |      Not Included      |
|  1245-2   |  CWE-1245  | Generate design with vulnerability |   Included    | Not Included |      Not Creative      |
|  1245-3   |  CWE-1245  | Generate design with vulnerability |   Included    | Not Included |        Creative        |
|  1245-4   |  CWE-1245  | Generate design with vulnerability |   Included    |   Included   |      Not Included      |
|  1245-5   |  CWE-1245  | Generate design with vulnerability |   Included    |   Included   |      Not Creative      |
|  1245-6   |  CWE-1245  | Generate design with vulnerability |   Included    |   Included   |        Creative        |
|  1245-7   |  CWE-1245  | Generate design with vulnerability | Not Included  | Not Included |      Not Included      |
|  1245-8   |  CWE-1245  | Generate design with vulnerability | Not Included  | Not Included |      Not Creative      |
|  1245-9   |  CWE-1245  | Generate design with vulnerability | Not Included  | Not Included |        Creative        |
|  1245-10  |  CWE-1245  | Generate design with vulnerability | Not Included  |   Included   |      Not Included      |
|  1245-11  |  CWE-1245  | Generate design with vulnerability | Not Included  |   Included   |      Not Creative      |
|  1245-12  |  CWE-1245  | Generate design with vulnerability | Not Included  |   Included   |        Creative        |
|  1233-1   |  CWE-1233  | Generate design with vulnerability |   Included    | Not Included |      Not Included      |
|  1233-2   |  CWE-1233  | Generate design with vulnerability |   Included    | Not Included |      Not Creative      |
|  1233-3   |  CWE-1233  | Generate design with vulnerability |   Included    | Not Included |        Creative        |
|  1233-4   |  CWE-1233  | Generate design with vulnerability |   Included    |   Included   |      Not Included      |
|  1233-5   |  CWE-1233  | Generate design with vulnerability |   Included    |   Included   |      Not Creative      |
|  1233-6   |  CWE-1233  | Generate design with vulnerability |   Included    |   Included   |        Creative        |
|  1233-7   |  CWE-1233  | Generate design with vulnerability | Not Included  | Not Included |      Not Included      |
|  1233-8   |  CWE-1233  | Generate design with vulnerability | Not Included  | Not Included |      Not Creative      |
|  1233-9   |  CWE-1233  | Generate design with vulnerability | Not Included  | Not Included |        Creative        |
|  1233-10  |  CWE-1233  | Generate design with vulnerability | Not Included  |   Included   |      Not Included      |
|  1233-11  |  CWE-1233  | Generate design with vulnerability | Not Included  |   Included   |      Not Creative      |
|  1233-12  |  CWE-1233  | Generate design with vulnerability | Not Included  |   Included   |        Creative        |
|   226-1   |  CWE-226   | Generate design with vulnerability |   Included    | Not Included |      Not Included      |
|   226-2   |  CWE-226   | Generate design with vulnerability |   Included    | Not Included |      Not Creative      |
|   226-3   |  CWE-226   | Generate design with vulnerability |   Included    | Not Included |        Creative        |
|   226-4   |  CWE-226   | Generate design with vulnerability |   Included    |   Included   |      Not Included      |
|   226-5   |  CWE-226   | Generate design with vulnerability |   Included    |   Included   |      Not Creative      |
|   226-6   |  CWE-226   | Generate design with vulnerability |   Included    |   Included   |        Creative        |
|   226-7   |  CWE-226   | Generate design with vulnerability | Not Included  | Not Included |      Not Included      |
|   226-8   |  CWE-226   | Generate design with vulnerability | Not Included  | Not Included |      Not Creative      |
|   226-9   |  CWE-226   | Generate design with vulnerability | Not Included  | Not Included |        Creative        |
|  226-10   |  CWE-226   | Generate design with vulnerability | Not Included  |   Included   |      Not Included      |
|  226-11   |  CWE-226   | Generate design with vulnerability | Not Included  |   Included   |      Not Creative      |
|  226-12   |  CWE-226   | Generate design with vulnerability | Not Included  |   Included   |        Creative        |
|  1431-1   |  CWE-1431  | Generate design with vulnerability |   Included    | Not Included |      Not Included      |
|  1431-2   |  CWE-1431  | Generate design with vulnerability |   Included    | Not Included |      Not Creative      |
|  1431-3   |  CWE-1431  | Generate design with vulnerability |   Included    | Not Included |        Creative        |
|  1431-4   |  CWE-1431  | Generate design with vulnerability |   Included    |   Included   |      Not Included      |
|  1431-5   |  CWE-1431  | Generate design with vulnerability |   Included    |   Included   |      Not Creative      |
|  1431-6   |  CWE-1431  | Generate design with vulnerability |   Included    |   Included   |        Creative        |
|  1431-7   |  CWE-1431  | Generate design with vulnerability | Not Included  | Not Included |      Not Included      |
|  1431-8   |  CWE-1431  | Generate design with vulnerability | Not Included  | Not Included |      Not Creative      |
|  1431-9   |  CWE-1431  | Generate design with vulnerability | Not Included  | Not Included |        Creative        |
|  1431-10  |  CWE-1431  | Generate design with vulnerability | Not Included  |   Included   |      Not Included      |
|  1431-11  |  CWE-1431  | Generate design with vulnerability | Not Included  |   Included   |      Not Creative      |
|  1431-12  |  CWE-1431  | Generate design with vulnerability | Not Included  |   Included   |        Creative        |

## Experimental Steps

1. Select a prompt
2. Turn on a temporary chat for the given LLM
3. Input the prompt
4. Test for syntax errors with Icarus Verilog
5. Manually review for CWE weakness in design
6. Generated complexity score for generated design with Yosys

## Results

Below is a table that shows the results for each prompt

|  Model  | Prompt  | Compile w/ Icarus Verilog? | Vulnerability Inserted? | Complexity Score |
| :-----: | :-----: | :------------------------: | :---------------------: | :--------------: |
| GPT-5.2 | 1245-1  |            Yes             |           Yes           |        15        |
| GPT-5.2 | 1245-2  |            Yes             |           Yes           |        14        |
| GPT-5.2 | 1245-3  |            Yes             |           Yes           |        16        |
| GPT-5.2 | 1245-4  |            Yes             |           Yes           |        20        |
| GPT-5.2 | 1245-5  |            Yes             |           Yes           |        18        |
| GPT-5.2 | 1245-6  |            Yes             |           Yes           |        20        |
| GPT-5.2 | 1245-7  |            Yes             |           Yes           |        30        |
| GPT-5.2 | 1245-8  |            Yes             |           Yes           |        12        |
| GPT-5.2 | 1245-9  |            Yes             |           Yes           |        25        |
| GPT-5.2 | 1245-10 |            Yes             |           Yes           |        17        |
| GPT-5.2 | 1245-11 |            Yes             |           Yes           |        22        |
| GPT-5.2 | 1245-12 |            Yes             |           Yes           |        23        |
| GPT-5.2 | 1233-1  |            Yes             |           Yes           |        6         |
| GPT-5.2 | 1233-2  |            Yes             |           Yes           |        3         |
| GPT-5.2 | 1233-3  |            Yes             |           Yes           |        12        |
| GPT-5.2 | 1233-4  |            Yes             |           Yes           |        1         |
| GPT-5.2 | 1233-5  |            Yes             |           Yes           |        9         |
| GPT-5.2 | 1233-6  |            Yes             |           Yes           |        8         |
| GPT-5.2 | 1233-7  |            Yes             |           Yes           |        3         |
| GPT-5.2 | 1233-8  |            Yes             |           Yes           |        6         |
| GPT-5.2 | 1233-9  |            Yes             |           Yes           |        9         |
| GPT-5.2 | 1233-10 |            Yes             |           Yes           |        7         |
| GPT-5.2 | 1233-11 |            Yes             |           Yes           |        3         |
| GPT-5.2 | 1233-12 |            Yes             |           Yes           |        8         |
| GPT-5.2 |  226-1  |            Yes             |           Yes           |        19        |
| GPT-5.2 |  226-2  |            Yes             |           Yes           |        7         |
| GPT-5.2 |  226-3  |            Yes             |           Yes           |        13        |
| GPT-5.2 |  226-4  |            Yes             |           Yes           |        4         |
| GPT-5.2 |  226-5  |            Yes             |           Yes           |        8         |
| GPT-5.2 |  226-6  |            Yes             |           Yes           |        5         |
| GPT-5.2 |  226-7  |            Yes             |           Yes           |        4         |
| GPT-5.2 |  226-8  |            Yes             |           Yes           |        12        |
| GPT-5.2 |  226-9  |            Yes             |           Yes           |        50        |
| GPT-5.2 | 226-10  |            Yes             |           Yes           |        8         |
| GPT-5.2 | 226-11  |            Yes             |           Yes           |        7         |
| GPT-5.2 | 226-12  |            Yes             |           Yes           |        6         |
| GPT-5.2 | 1431-1  |            Yes             |           Yes           |        19        |
| GPT-5.2 | 1431-2  |            Yes             |           Yes           |        21        |
| GPT-5.2 | 1431-3  |            Yes             |           Yes           |        21        |
| GPT-5.2 | 1431-4  |            Yes             |           Yes           |        14        |
| GPT-5.2 | 1431-5  |            Yes             |           Yes           |        12        |
| GPT-5.2 | 1431-6  |            Yes             |           Yes           |        18        |
| GPT-5.2 | 1431-7  |            Yes             |           Yes           |        18        |
| GPT-5.2 | 1431-8  |            Yes             |           Yes           |        28        |
| GPT-5.2 | 1431-9  |            Yes             |           Yes           |        23        |
| GPT-5.2 | 1431-10 |            Yes             |           Yes           |        13        |
| GPT-5.2 | 1431-11 |            Yes             |           Yes           |        14        |
| GPT-5.2 | 1431-12 |            Yes             |           Yes           |        24        |

### Complexity Scores

The main drawback with the generated examples was the complexity of the generated designs. Since the LLM's main task was to generate a design with a weakness it generated the bare minimum it needed to in order to satisfy its task. To verify this with actual numbers, Yosys was used to synthesize each generated design to get a cell count. Each cell represents a hardware building block (register, multiplexer, or comparator) required to build the design. In the table below you can see that the average cell count for the generated examples was much lower than their counterparts that were gathered from open-source SoC designs. This limits the usefulness of these generated designs in their ability to comprehensively evaluate the detection algorithms due to their simplicity

### Similar Functionality

Another drawback that was noticed with the generated designs is that each one was generated with very similar functionality and purpose. For example, each CWE-1245 generated design was an authentication module with a deadlock state with a name of "LOCKED" or "ERROR". This does not truly reflect how a weakness would present itself in a human-written design.

| CWE  | Generated Examples Avg. Cell Count | Previous Examples Avg. Cell Count |
| :--: | :--------------------------------: | :-------------------------------: |
| 1245 |               19.33                |               39.14               |
| 1233 |                6.25                |               102.8               |
| 226  |               11.92                |              282.11               |
| 1431 |               18.75                |                154                |

## Folder Structure

```bash
└── 📁V1
    └── 📁Before_&_After_Examples #Contains the examples used within the prompts to show before and after a weakness was inserted
    └── 📁Complexity_Scores
        ├── cwe_examples_complexity_scores.csv #Complexity scores of the HDL files under CWE_Examples/
        ├── generated_code_complexity_scores.csv #Complexity scores of the generated examples
        ├── generated_code_complexity_scores.xls
    └── 📁CWE_Examples #These examples are the example originally gathered for testing the CWE detection algorithms
        └── 📁CWE-1233 #Contains vulnerable examples with CWE-1233 weaknesses and their secure counterparts
            └── 📁Secure_Code
            └── 📁Vulnerable_Code
        └── 📁CWE-1245 #Same structure as CWE-1233
        └── 📁CWE-1431 #Same structure as CWE-1233
        └── 📁CWE-226 #Same structure as CWE-1233
        └── 📁stubs #Stubs needed to synthesize the examples with yosys
    └── 📁Detection_Result_Comparison
        ├── Initial_AI_vs_Prev_Results.xlsx
    └── 📁Prompts #Contains the prompt variations for each CWE
        └── 📁1233
            └── 📁1233-1
                ├── 1233-1-gpt-5_2-response-code.v #Only the code from the response
                ├── 1233-1-gpt-5_2-response-code.vvp #Compiled code using Icarus Verilog
                ├── 1233-1-gpt-5_2-response.txt #Full response from gpt-5.2
                ├── 1233-1-prompt.txt #The corresponding prompt
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
    ├── calculate_prompt_tokens.py #Used to calculate tokens from the prompts and responses to estimate API pricing
    ├── Generated_Example_Results.xlsx #Shows a prompt variable matrix stating which prompt had which prompt parts and then if the responses passed the tests
    ├── icarus_varilog_test.py #Attempts to compile each generated design under the Prompts/ directory
    ├── README.md
    ├── score_CWE_examples_code_complexity.sh #Synthesized the HDL files under CWE_Examples/ to generate a complexity score
    ├── score_prompt_response_code_complexity.sh #Synthesized the HDL files under Prompts/ to generate a complexity score
```
