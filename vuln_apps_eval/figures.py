import matplotlib.pyplot as plt
import numpy as np
import json
import os

project_name = "dvna"
thresholds = [0, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]
precision = []
recall = []
f1 = []
tp_counts = []
fp_counts = []
fn_counts = []

results_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), project_name)

# filtered data
for value in thresholds:
    if value == 0:
        with open(os.path.join(results_path, "results3.json"), "r") as f:
            results = json.load(f)
    else:
        with open(os.path.join(results_path, f"results3filtered{str(int(value*100))}.json"), "r") as f:
            results = json.load(f)
    precision.append(results['metrics']["precision"])
    recall.append(results['metrics']["recall"])
    f1.append(results['metrics']["f1_score"])
    tp_counts.append(results['metrics']["true_positives"])
    fp_counts.append(results['metrics']["false_positives"])
    fn_counts.append(results['metrics']["false_negatives"])

total_vulns = tp_counts[0] + fn_counts[0]

# baseline data
with open(os.path.join(results_path, "results_default.json"), "r") as f:
    results = json.load(f)
precision_baseline = results['metrics']["precision"]
recall_baseline = results['metrics']["recall"]
f1_baseline = results['metrics']["f1_score"]
tp_baseline = results['metrics']["true_positives"]
fp_baseline = results['metrics']["false_positives"]
fn_baseline = results['metrics']["false_negatives"]

# semgrep data
with open(os.path.join(results_path, "results_semgrep.json"), "r") as f:
    results = json.load(f)
precision_semgrep = results['metrics']["precision"]
recall_semgrep = results['metrics']["recall"]
f1_semgrep = results['metrics']["f1_score"]
tp_semgrep = results['metrics']["true_positives"]
fp_semgrep = results['metrics']["false_positives"]
fn_semgrep = results['metrics']["false_negatives"]

# njsscan data
with open(os.path.join(results_path, "results_njsscan.json"), "r") as f:
    results = json.load(f)
precision_njsscan = results['metrics']["precision"]
recall_njsscan = results['metrics']["recall"]
f1_njsscan = results['metrics']["f1_score"]
tp_njsscan = results['metrics']["true_positives"]
fp_njsscan = results['metrics']["false_positives"]
fn_njsscan = results['metrics']["false_negatives"]


#=== FIGURE 1 ALL IN ONE PLOT ==#
plt.figure(figsize=(10, 6))

# plot baseline (horizontal dashed)
plt.axhline(y=precision_baseline, color='blue', linestyle='--', linewidth=1.5, alpha=0.5, label='Precision Baseline')
plt.axhline(y=recall_baseline, color='green', linestyle='--', linewidth=1.5, alpha=0.5, label='Recall Baseline')
plt.axhline(y=f1_baseline, color='red', linestyle='--', linewidth=1.5, alpha=0.5, label='F1 Score Baseline')

# plot metrics vs thresholds
plt.plot(thresholds, precision, marker='o', color='blue', linewidth=2.5, markersize=8, label='Precision')
plt.plot(thresholds, recall, marker='o', color='green', linewidth=2.5, markersize=8, label='Recall')
plt.plot(thresholds, f1, marker='o', color='red', linewidth=2.5, markersize=8, label='F1 Score')

# labels and title
plt.xlabel('Threshold', fontsize=14, fontweight='bold')
plt.ylabel('Percentage (%)', fontsize=14, fontweight='bold')
plt.title('Effect of Filtering Threshold on Evaluation Metrics', fontsize=16, fontweight='bold', pad=20)

plt.grid(True, linestyle=':', alpha=0.6)
plt.legend(loc='best', fontsize=11, framealpha=0.9)

plt.xticks(thresholds, fontsize=12)
plt.yticks(fontsize=12)
plt.ylim(0, 100)
plt.tight_layout()
plt.savefig(os.path.join(results_path, "metrics_vs_thresholds.png"), dpi=300, bbox_inches='tight')

#=== FIGURE 2 THREE SUBPLOTS ==#

fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))

# precision
ax1.plot(thresholds, precision, marker='o', color='blue', linewidth=2.5, markersize=8, label='Proposed System')
ax1.axhline(y=precision_baseline, color='purple', linestyle='--', linewidth=1.5, alpha=0.6, label='CodeQL Baseline')
ax1.axhline(y=precision_semgrep, color='orange', linestyle='--', linewidth=1.5, alpha=0.6, label='Semgrep Baseline')
ax1.axhline(y=precision_njsscan, color='dimgrey', linestyle='--', linewidth=1.5, alpha=0.6, label='NJSScan Baseline')
ax1.set_xlabel('Threshold', fontsize=12, fontweight='bold')
ax1.set_ylabel('Precision (%)', fontsize=12, fontweight='bold')
ax1.set_title('Precision vs Threshold', fontsize=14, fontweight='bold', pad=15)
ax1.grid(True, linestyle=':', alpha=0.5)
ax1.legend(loc='best', fontsize=10, framealpha=0.9)
ax1.set_xticks(thresholds)
ax1.set_xticklabels(thresholds, fontsize=8, rotation=45)
ax1.set_ylim(0, 100)

# recall
ax2.plot(thresholds, recall, marker='o', color='green', linewidth=2.5, markersize=8, label='Proposed System')
ax2.axhline(y=recall_baseline, color='purple', linestyle='--', linewidth=1.5, alpha=0.6, label='CodeQL Baseline')
ax2.axhline(y=recall_semgrep, color='orange', linestyle='--', linewidth=1.5, alpha=0.6, label='Semgrep Baseline')
ax2.axhline(y=recall_njsscan, color='dimgrey', linestyle='--', linewidth=1.5, alpha=0.6, label='NJSScan Baseline')
ax2.set_xlabel('Threshold', fontsize=12, fontweight='bold')
ax2.set_ylabel('Recall (%)', fontsize=12, fontweight='bold')
ax2.set_title('Recall vs Threshold', fontsize=14, fontweight='bold', pad=15)
ax2.grid(True, linestyle=':', alpha=0.5)
ax2.legend(loc='best', fontsize=10, framealpha=0.9)
ax2.set_xticks(thresholds)
ax2.set_xticklabels(thresholds, fontsize=8, rotation=45)
ax2.set_ylim(0, 100)

# f1 score
ax3.plot(thresholds, f1, marker='o', color='red', linewidth=2.5, markersize=8, label='Proposed System')
ax3.axhline(y=f1_baseline, color='purple', linestyle='--', linewidth=1.5, alpha=0.6, label='CodeQL Baseline')
ax3.axhline(y=f1_semgrep, color='orange', linestyle='--', linewidth=1.5, alpha=0.6, label='Semgrep Baseline')
ax3.axhline(y=f1_njsscan, color='dimgrey', linestyle='--', linewidth=1.5, alpha=0.6, label='NJSScan Baseline')
ax3.set_xlabel('Threshold', fontsize=12, fontweight='bold')
ax3.set_ylabel('F1 Score (%)', fontsize=12, fontweight='bold')
ax3.set_title('F1 Score vs Threshold', fontsize=14, fontweight='bold', pad=15)
ax3.grid(True, linestyle=':', alpha=0.5)
ax3.legend(loc='best', fontsize=10, framealpha=0.9)
ax3.set_xticks(thresholds)
ax3.set_xticklabels(thresholds, fontsize=8, rotation=45)
ax3.set_ylim(0, 100)

fig.suptitle('Effect of Filtering Threshold on Evaluation Metrics', fontsize=16, fontweight='bold', y=0.96)
plt.tight_layout()
plt.savefig(os.path.join(results_path, "metrics_vs_thresholds_subplots.png"), dpi=300, bbox_inches='tight')

#=== FIGURE 3 PRECISION-RECALL CURVE ===#
plt.figure(figsize=(10,8))

plt.plot(recall, precision, marker='o', color='blue', linewidth=2.5, markersize=10, label='Proposed System', zorder=3)

for i, value in enumerate(thresholds):
    plt.annotate(f'{value}', xy=(recall[i], precision[i]), textcoords="offset points", xytext=(8, 8), fontsize=9,
                 bbox=dict(boxstyle="round,pad=0.3", fc='white', edgecolor='grey', alpha=0.9))
    
plt.scatter(recall_baseline, precision_baseline, color='purple', s=200, marker='X', edgecolors='black', linewidths=1.5 ,label='CodeQL Baseline', zorder=4)
plt.scatter(recall_semgrep, precision_semgrep, color='orange', s=200, marker='X', edgecolors='black', linewidths=1.5 ,label='Semgrep Baseline', zorder=4)
plt.scatter(recall_njsscan, precision_njsscan, color='dimgrey', s=200, marker='X', edgecolors='black', linewidths=1.5 ,label='NJSScan Baseline', zorder=4)

plt.xlabel('Recall (%)', fontsize=14, fontweight='bold')
plt.ylabel('Precision (%)', fontsize=14, fontweight='bold')
plt.title('Precision-Recall Curve', fontsize=16, fontweight='bold', pad=20)
plt.grid(True, linestyle=':', alpha=0.6)
plt.legend(loc='best', fontsize=12, framealpha=0.9)
plt.xlim(0, 100)
plt.ylim(0, 100)
plt.tight_layout()

plt.savefig(os.path.join(results_path, "precision_recall_curve.png"), dpi=300, bbox_inches='tight')

#== FIGURE 4 TP/FP vs THRESHOLDS ==#
fig, ax1 = plt.subplots(figsize=(10,6))

# left y for tp
ax1.set_xlabel('Threshold', fontsize=14, fontweight='bold')
ax1.set_ylabel('True Positives', color='green', fontsize=13, fontweight='bold')
ax1.plot(thresholds, tp_counts, marker='o', color='green', linewidth=2.5, markersize=8, label='True Positives')
ax1.tick_params(axis='y', labelcolor='green')
ax1.set_xticks(thresholds)
ax1.grid(True, linestyle=':', alpha=0.4)
ax1.set_ylim(0, total_vulns+4)

ax1.axhline(y=total_vulns, color='blue', linestyle='--', linewidth=1.5, alpha=0.5, label=f'Total Vulnerabilities ({total_vulns})')

# right y for fp
ax2 = ax1.twinx()
ax2.set_ylabel('False Positives', color='red', fontsize=13, fontweight='bold')
ax2.plot(thresholds, fp_counts, marker='s', color='red', linewidth=2.5, markersize=8, label='False Positives')
ax2.tick_params(axis='y', labelcolor='red')

plt.title('True Positives and False Positives vs Threshold', fontsize=16, fontweight='bold', pad=20)

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='best', fontsize=11, framealpha=0.9)
plt.tight_layout()
plt.savefig(os.path.join(results_path, "tp_fp_counts.png"), dpi=300, bbox_inches='tight')

#== FIGURE 5 TP FP STACKED BAR CHART ==#
fig, ax = plt.subplots(figsize=(12,6))
x_pos = np.arange(len(thresholds))
width = 0.6

p1 = ax.bar(x_pos, tp_counts, width, label='True Positives', color='green')
p2 = ax.bar(x_pos, fp_counts, width, bottom=tp_counts, label='False Positives', color='red')

ax.set_xlabel('Threshold', fontsize=14, fontweight='bold')
ax.set_ylabel('Count', fontsize=14, fontweight='bold')
ax.set_title('Detection Breakdown vs Threshold', fontsize=16, fontweight='bold', pad=20)
ax.set_xticks(x_pos)
ax.set_xticklabels(thresholds)
ax.axhline(y=total_vulns, color='black', linestyle='--', linewidth=1.5, alpha=0.5, label=f'Total Vulnerabilities ({total_vulns})')
ax.legend(loc='upper right', fontsize=12, framealpha=0.9)
ax.grid(True, axis='y', linestyle=':', alpha=0.4)


plt.tight_layout()
plt.savefig(os.path.join(results_path, "tp_fp_stacked_bar_chart.png"), dpi=300, bbox_inches='tight')

#== FIGURE 6 GROUPED BAR CHART TP FP ==#
fig, ax = plt.subplots(figsize=(12,6))

thresholds_with_baseline = ['NJSScan','Semgrep', 'CodeQL Baseline'] + thresholds
tp_with_baseline = [tp_njsscan, tp_semgrep, tp_baseline] + tp_counts
fp_with_baseline = [fp_njsscan, fp_semgrep, fp_baseline] + fp_counts

x_pos = np.arange(len(thresholds_with_baseline))
width = 0.35

bars1 = ax.bar(x_pos - width/2, tp_with_baseline, width, label='True Positives', color='green', edgecolor='black', linewidth=0.5)
bars2 = ax.bar(x_pos + width/2, fp_with_baseline, width, label='False Positives', color='red', edgecolor='black', linewidth=0.5)

for bar in bars1:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height,
            f'{int(height)}',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

for bar in bars2:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height,
            f'{int(height)}',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

ax.set_xlabel('Threshold', fontsize=14, fontweight='bold')
ax.set_ylabel('Count', fontsize=14, fontweight='bold')
ax.set_title('True Positives and False Positives vs Threshold', fontsize=16, fontweight='bold', pad=20)
ax.set_xticks(x_pos)
ax.set_xticklabels(thresholds_with_baseline)


ax.legend(loc='upper right', fontsize=12, framealpha=0.9)
ax.grid(True, axis='y', linestyle=':', alpha=0.4)

ax.axhline(y=total_vulns, color='black', linestyle='--', linewidth=1.5, alpha=0.5, 
           label=f'Total Vulnerabilities')

current_yticks = list(ax.get_yticks())
if total_vulns not in current_yticks:
    current_yticks.append(total_vulns)
    current_yticks.sort()

ax.set_yticks(current_yticks)
yticklabels = [f'{int(tick)}' if tick != total_vulns else total_vulns for tick in current_yticks]
ax.set_yticklabels(yticklabels, fontsize=10)

for tick, label in zip(ax.yaxis.get_major_ticks(), yticklabels):
    if str(total_vulns) in str(label):
        tick.label1.set_fontweight('bold')
        tick.label1.set_color('black')

handles, labels = ax.get_legend_handles_labels()
ax.legend(handles, labels, loc='upper right', fontsize=12, framealpha=0.9)

plt.tight_layout()
plt.savefig(os.path.join(results_path, "tp_fp_grouped_bars.png"), dpi=300, bbox_inches='tight')