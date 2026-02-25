#Conversion
# 1 token ~= 4 characters
# 1 token ~= 0.75 words
# 100 tokens ~= 75 words


#Count the number of words in the prompts and responses to estimate token usage


cwe_prefixes = ["1245", "1233", "226", "1431"]
prompts_dir = "C:/Users/parks/OneDrive/Documents/UC/Research/Spring_2026/Initial_AI_Testing/Prompts"

prompt_words = []
response_words = []

num_prompt_words = 0
num_response_words = 0

for prefix in cwe_prefixes:
    for i in range(1, 13):
        prompt_id_dir = prompts_dir + f"/{prefix}" + f"/{prefix}-{i}"
        prompt_file_path = prompt_id_dir + f"/{prefix}-{i}-prompt.txt"
        response_file_path = prompt_id_dir + f"/{prefix}-{i}-gpt-5_2-response.txt"

        with open(prompt_file_path, 'r', encoding='utf-8') as prompt_file:
            prompt_text = prompt_file.read()
            num_words = len(prompt_text.split())
            num_prompt_words += num_words
            prompt_words.append(num_words)

        with open(response_file_path, 'r', encoding='utf-8') as response_file:
            response_text = response_file.read()
            num_words = len(response_text.split())
            num_response_words += num_words
            response_words.append(num_words) 

num_input_tokens = num_prompt_words / 0.75
num_output_tokens = num_response_words / 0.75

estimated_input_cost = (num_input_tokens / 1000000) * 1.75
estimated_output_cost = (num_output_tokens / 1000000) * 14.00

print("INPUT PRICING ESTIMATE")
print(f"Average number of prompt words: {sum(prompt_words) / len(prompt_words)}")
print(f"Shortest Prompt: {min(prompt_words)} words")
print(f"Longest Prompt: {max(prompt_words)} words")
print(f"Total number of prompt words: {num_prompt_words}")
print(f"Estimated number of input tokens: {num_input_tokens}")
print(f"Estimated input cost: ${estimated_input_cost:.6f}")
print("--------------------------------------------------")
print("OUTPUT PRICING ESTIMATE")
print(f"Average number of response words: {sum(response_words) / len(response_words)}")
print(f"Shortest response: {min(response_words)} words")
print(f"Longest response: {max(response_words)} words")
print(f"Total number of response words: {num_response_words}")
print(f"Estimated number of output tokens: {num_output_tokens}")
print(f"Estimated output cost: ${estimated_output_cost:.6f}")
print("--------------------------------------------------")
print("TOTAL PRICING ESTIMATE")
print(f"Estimated total cost: ${estimated_input_cost + estimated_output_cost:.6f}")
