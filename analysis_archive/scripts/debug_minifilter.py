import os, re
# 搜索所有日志文件中 MinifilterNeutralizer 相关信息
out = []
log_files = []
for root, dirs, files in os.walk(r'D:\技术研发'):
    for f in files:
        if 'sd' in f.lower() and f.endswith(('.log', '.txt')):
            p = os.path.join(root, f)
            log_files.append(p)

out.append(f'找到 {len(log_files)} 个日志文件')
out.append('')

# 搜索关键字
keywords = ['FLT:', 'NTRL', 'minifilter', 'MessageTransfer', 'B553:GP', 'NeutralizeMessageTransfer',
            'IsMessageTransferNeutralized', 'FltGlobals', 'FilterList', 'FLT_FILTER',
            'Operations', 'GuardPac', 'ReapplyAllCallbacks', 'CB:REAPPLIED',
            'pac=', 'PAC', 'PacStatus', 'DisablePac', 'VerifyFltPipeline']

for lf in log_files:
    try:
        data = open(lf, 'rb').read()
        text = data.decode('utf-8', errors='replace')
        lines = text.split('\n')
        matches = []
        for line in lines:
            if any(k in line for k in keywords):
                matches.append(line.strip())
        if matches:
            out.append(f'=== {lf} ({len(matches)} matches) ===')
            # 只显示前 50 行避免过长
            for m in matches[:50]:
                out.append(f'  {m}')
            if len(matches) > 50:
                out.append(f'  ... ({len(matches)-50} more)')
            out.append('')
    except Exception as e:
        out.append(f'Error reading {lf}: {e}')

open(r'D:\技术研发\minifilter_debug.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, {len(out)} lines')
