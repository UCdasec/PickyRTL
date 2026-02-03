import pandas as pd
import re

file_path = "C:/Users/parks/OneDrive/Documents/UC/Research/DetectRTL/CWE_Detection/Results/9-18-register-matching-trials/comparisons.xlsx"
df = pd.read_excel(file_path)

ground_truth_col = "Security Sensitive Registers"
predition_cols = df.columns[2:]

def parse_registers(cell):
    if pd.isna(cell):
        return []
    if isinstance(cell, list):
        return cell
    if isinstance(cell, str):
        cleaned = re.sub(r"[\[\]']", "", cell)
        return [x.strip() for x in cleaned.split(",")]

    return []

ground_truth = {
    idx: set(parse_registers(row[ground_truth_col]))
    for idx, row in df.iterrows()
}
    
results = []
for col in predition_cols:
    tp_list, fp_list, fn_list = [], [], []
    for idx, row in df.iterrows():
        gt = ground_truth[idx]
        pred = set(parse_registers(row[col]))
        
        tp = gt & pred
        fp = pred - gt
        fn = gt - pred

        tp_list.append(len(tp))
        fp_list.append(len(fp))
        fn_list.append(len(fn))

    num_tp = sum(tp_list)
    num_fp = sum(fp_list)
    num_fn = sum(fn_list)
    results.append({
    "Matching Type": col,
    "TP": num_tp,
    "FP": num_fp,
    "FN": num_fn,
    "Precision": float(f"{num_tp/(num_tp + num_fp):.3f}"),
    "Recall": float(f"{num_tp/(num_tp + num_fn):.3f}")
    })

results_df = pd.DataFrame(results)

with pd.ExcelWriter(file_path, mode='a', if_sheet_exists="replace") as writer:
    results_df.to_excel(writer, sheet_name="Results", index=False)