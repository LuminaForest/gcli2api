// =====================================================================
// 批量生成 GCLI 凭证文件
// =====================================================================

(function() {
    const BATCH_PROXY_CONFIG_KEY = 'batch_generate_proxy_url';

    const state = {
        selectedFile: null,
        generatorUrl: '',
        currentProxyUrl: '',
        isGeneratingProxy: false,
        activeTaskId: '',
        activeTaskDone: null,
        lastTaskLogSeq: 0,
        logPollTimer: null,
        accounts: [],
        failedAccounts: [],
        existingCredentialEmails: new Set(),
        isBatchRunning: false
    };

    function getElement(id) {
        return document.getElementById(id);
    }

    function setText(id, value) {
        const element = getElement(id);
        if (element) element.textContent = value;
    }

    function appendLog(message, reset = false) {
        const element = getElement('batchGenerateLogContent');
        if (!element) return;

        const time = new Date().toLocaleTimeString();
        const line = `[${time}] ${message}`;
        if (reset || element.textContent.trim() === '等待开始生成...') {
            element.textContent = line;
        } else {
            element.textContent += `\n${line}`;
        }
        element.scrollTop = element.scrollHeight;
    }

    function setAccountStatus(message = '', type = 'info') {
        const element = getElement('batchGenerateAccountStatus');
        if (!element) return;

        if (!message) {
            element.style.display = 'none';
            element.textContent = '';
            return;
        }

        const styles = {
            info: ['#d0d7de', '#fff', '#24292f'],
            success: ['#2da44e', '#dafbe1', '#116329'],
            warning: ['#d4a72c', '#fff8c5', '#7d4e00'],
            error: ['#cf222e', '#ffebe9', '#82071e']
        };
        const [borderColor, backgroundColor, color] = styles[type] || styles.info;
        element.style.display = 'block';
        element.style.borderColor = borderColor;
        element.style.background = backgroundColor;
        element.style.color = color;
        element.style.whiteSpace = 'pre-wrap';
        element.style.wordBreak = 'break-word';
        element.textContent = message;
    }

    function formatFailureReason(reason) {
        const value = String(reason || '').trim();
        const labels = {
            qr_required: '二维码验证',
            automation_failed: '登录自动化失败',
            credential_missing: '未生成临时凭证',
            credential_persist_failed: '保存凭证或绑定代理失败',
            validation_failed: '账号验证未完成',
            phone_option_missing: '未提供 Verify your phone number，账号不可用',
            phone_rate_limited: '当前手机号异常，已被用于验证过多次',
            service_unavailable: '页面提示 Entire service unavailable，账号不可用',
            open_failed: '打开验证页失败',
            code_fetch_failed: '获取短信验证码失败',
            code_submit_failed: '提交短信验证码失败',
            code_input_timeout: '等待短信验证码页超时',
            page_load_failed: '页面加载失败',
            phone_method_not_selected: '手机号验证方式未选择',
            phone_input_timeout: '等待手机号输入页超时',
            phone_input_not_found: '未找到手机号输入框',
            phone_next_not_triggered: '手机号下一步未触发',
            page_load_timeout: '验证页加载超时',
            submitted_wait_timeout: '等待验证完成超时',
            phone_required_but_not_submitted: '手机号验证未完成',
            model_test_not_200: '模型测试未通过，未保存凭证'
        };
        return labels[value] || value;
    }

    function getFailureReason(result) {
        return String(result?.failure_reason || result?.status || result?.error || '').trim();
    }

    function getFinalTestStatusCode(result) {
        return Number(result?.final_test_status_code || 0);
    }

    function normalizeEmail(value) {
        return String(value || '').trim().toLowerCase();
    }

    function isPageLoadFailure(result) {
        const reason = getFailureReason(result);
        const retryableReasons = new Set([
            'page_load_failed',
            'open_failed',
            'page_load_timeout'
        ]);
        if (retryableReasons.has(reason)) return true;

        const error = String(result?.error || '').toLowerCase();
        return reason === 'automation_failed' && (
            error.includes('page.goto') ||
            error.includes('net::err_') ||
            error.includes('err_connection') ||
            error.includes('err_tunnel') ||
            error.includes('err_proxy') ||
            error.includes('proxyerror') ||
            error.includes('connecterror') ||
            error.includes('proxy authentication required') ||
            error.includes('407 proxy authentication required') ||
            error.includes('invalid full account format') ||
            error.includes('connection closed') ||
            error.includes('connection reset') ||
            error.includes('connection timed out') ||
            error.includes('navigation timeout')
        );
    }

    function recordFailedAccount(account, reason) {
        const email = String(account?.email || '').trim();
        if (!email) return;

        state.failedAccounts.push({
            line_number: account.line_number,
            email,
            reason: formatFailureReason(reason)
        });
    }

    function formatFailedAccounts() {
        return state.failedAccounts
            .map(item => {
                const line = item.line_number ? `第 ${item.line_number} 行 ` : '';
                const reason = item.reason ? `（${item.reason}）` : '';
                return `${line}${item.email}${reason}`;
            })
            .join('，');
    }

    function setStartButtonDisabled(disabled) {
        const button = getElement('batchGenerateStartBtn');
        if (!button) return;
        button.disabled = Boolean(disabled);
        button.textContent = disabled ? '生成中...' : '开始生成';
    }

    function stopLogPolling() {
        if (state.logPollTimer) {
            clearInterval(state.logPollTimer);
            state.logPollTimer = null;
        }
    }

    function finishActiveTask(data) {
        const callback = state.activeTaskDone;
        state.activeTaskDone = null;
        stopLogPolling();
        if (typeof callback === 'function') callback(data || {});
    }

    function appendTaskLogs(logs) {
        (logs || []).forEach(log => {
            state.lastTaskLogSeq = Math.max(state.lastTaskLogSeq, Number(log.seq) || 0);
            const prefix = log.level === 'warning'
                ? '警告: '
                : (log.level === 'error' ? '错误: ' : '');
            appendLog(`${prefix}${log.message}`);
        });
    }

    async function pollTaskLogs() {
        if (!state.activeTaskId) return;

        try {
            const response = await fetch(
                `./batch-generate/logs/${encodeURIComponent(state.activeTaskId)}?since=${state.lastTaskLogSeq}`,
                { headers: getAuthHeaderValues() }
            );
            const data = await response.json();

            if (!response.ok) {
                appendLog(`日志获取失败: ${data.detail || data.error || '未知错误'}`);
                finishActiveTask({ status: 'failed', error: data.detail || data.error || '日志获取失败' });
                return;
            }

            appendTaskLogs(data.logs);

            if (data.status === 'completed') {
                appendLog('后台登录任务已结束');
                finishActiveTask(data);
            } else if (data.status === 'unusable' || data.account_unusable) {
                const reason = formatFailureReason(data.failure_reason || '账号不可用');
                appendLog(`账号 ${data.email || ''} 不可用（${reason}），已准备继续下一行`);
                finishActiveTask(data);
            } else if (data.status === 'failed') {
                appendLog('后台登录任务失败');
                finishActiveTask(data);
            }
        } catch (error) {
            appendLog(`日志获取失败: ${error.message}`);
            finishActiveTask({ status: 'failed', error: error.message });
        }
    }

    function startLogPolling(taskId, onDone) {
        stopLogPolling();
        state.activeTaskId = taskId || '';
        state.activeTaskDone = typeof onDone === 'function' ? onDone : null;
        state.lastTaskLogSeq = 0;
        if (!state.activeTaskId) return;

        pollTaskLogs();
        state.logPollTimer = setInterval(pollTaskLogs, 1500);
    }

    function waitForTask(taskId) {
        return new Promise(resolve => startLogPolling(taskId, resolve));
    }

    function getAuthHeaderValues() {
        if (typeof getAuthHeaders === 'function') return getAuthHeaders();
        return { 'Content-Type': 'application/json' };
    }

    function getConfiguredGeneratorUrl() {
        if (state.generatorUrl) return state.generatorUrl;
        if (typeof AppState !== 'undefined' && AppState.currentConfig) {
            return AppState.currentConfig.credential_proxy_generator_url || '';
        }
        return '';
    }

    function escapeText(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function updateProxyDisplay() {
        setText('batchGenerateProxyUrl', state.currentProxyUrl || '未生成代理地址');
    }

    function toHttpProxyUrl(proxyUrl) {
        const value = String(proxyUrl || '').trim();
        if (!value) return '';
        return `http://${value.includes('://') ? value.split('://', 2)[1] : value}`;
    }

    async function saveBatchGenerateProxyUrl(proxyUrl) {
        const response = await fetch('/config/save', {
            method: 'POST',
            headers: getAuthHeaderValues(),
            body: JSON.stringify({
                config: {
                    [BATCH_PROXY_CONFIG_KEY]: proxyUrl
                }
            })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || data.error || '未知错误');
        }
        if (typeof AppState !== 'undefined' && AppState.currentConfig) {
            AppState.currentConfig[BATCH_PROXY_CONFIG_KEY] = proxyUrl;
        }
    }

    async function generateAndSaveProxy(options = {}) {
        if (state.isGeneratingProxy) return '';

        const button = getElement('batchGenerateSwitchProxyBtn');
        const generatorUrl = getConfiguredGeneratorUrl().trim();
        const originalText = button ? button.textContent.trim() : '';
        const isAuto = Boolean(options.auto);

        if (!generatorUrl) {
            showStatus('请先在代理池管理中填写并保存凭证代理生成链接', 'error');
            return '';
        }

        try {
            state.isGeneratingProxy = true;
            if (button) {
                button.disabled = true;
                button.textContent = isAuto ? '自动生成中...' : '生成中...';
            }

            const response = await fetch('/config/proxy-pool/generate', {
                method: 'POST',
                headers: getAuthHeaderValues(),
                body: JSON.stringify({
                    generator_url: generatorUrl,
                    scheme: 'http'
                })
            });
            const data = await response.json();

            if (!response.ok) {
            showStatus(`${isAuto ? '自动生成代理地址' : '切换代理地址'}失败: ${data.detail || data.error || '未知错误'}`, 'error');
                return '';
            }

            const generatedUrl = toHttpProxyUrl(data.url);
            await saveBatchGenerateProxyUrl(generatedUrl);
            state.currentProxyUrl = generatedUrl;
            updateProxyDisplay();
            showStatus(isAuto ? '已自动生成并保存代理地址' : '代理地址已切换并保存', 'success');
            return generatedUrl;
        } catch (error) {
            showStatus(`${isAuto ? '自动生成代理地址' : '切换代理地址'}失败: ${error.message}`, 'error');
            return '';
        } finally {
            state.isGeneratingProxy = false;
            if (button) {
                button.disabled = false;
                button.textContent = originalText || '切换代理地址';
            }
        }
    }

    function updateFileList() {
        const section = getElement('batchGenerateFileListSection');
        const list = getElement('batchGenerateFileList');
        if (!section || !list) return;

        if (!state.selectedFile) {
            section.classList.add('hidden');
            list.innerHTML = '';
            return;
        }

        section.classList.remove('hidden');
        const sizeText = typeof formatFileSize === 'function'
            ? formatFileSize(state.selectedFile.size)
            : `${state.selectedFile.size} B`;
        list.innerHTML = `
            <div class="file-item">
                <div>
                    <span class="file-name">📄 ${escapeText(state.selectedFile.name)}</span>
                    <span class="file-size">(${sizeText}，TXT文件)</span>
                </div>
                <button type="button" class="remove-btn" onclick="window.BatchGenerate.clearFile()">删除</button>
            </div>
        `;
    }

    function isTxtFile(file) {
        return Boolean(file) && (
            file.name.toLowerCase().endsWith('.txt') ||
            file.type === 'text/plain'
        );
    }

    function setFile(file) {
        if (!isTxtFile(file)) {
            showStatus(`文件 ${file ? file.name : ''} 格式不支持，只支持TXT文件`, 'error');
            return;
        }

        state.selectedFile = file;
        updateFileList();
        const sizeText = typeof formatFileSize === 'function'
            ? formatFileSize(file.size)
            : `${file.size} B`;
        appendLog(`已选择文件: ${file.name} (${sizeText})`, true);
    }

    function parseAccountLine(line, lineNumber = 1) {
        const parts = String(line || '').split('|').map(part => part.trim());
        if (parts.length < 2 || !parts[0] || !parts[1]) {
            throw new Error(`第 ${lineNumber} 行格式不正确，至少需要：谷歌账号|密码`);
        }

        return {
            line_number: lineNumber,
            email: parts[0],
            password: parts[1],
            two_fa_key: parts[2] || '',
            phone: parts[3] || '',
            phone_code_url: parts[4] || ''
        };
    }

    async function submitAccount(account, index, total) {
        if (!state.currentProxyUrl) {
            appendLog('当前没有代理地址，正在自动生成代理地址...');
            await generateAndSaveProxy({ auto: true });
            if (!state.currentProxyUrl) {
                throw new Error('未生成代理地址，请先检查凭证代理生成链接');
            }
        }

        appendLog(`将使用代理地址提交登录任务: ${state.currentProxyUrl}`);
        appendLog(`正在提交第 ${index + 1}/${total} 行账号到后台自动化任务...`);
        const response = await fetch('./batch-generate/login-first', {
            method: 'POST',
            headers: getAuthHeaderValues(),
            body: JSON.stringify({
                ...account,
                proxy_url: state.currentProxyUrl || ''
            })
        });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || data.error || '未知错误');
        }

        if (data.task_id) {
            appendLog(`已创建后台登录任务: ${data.task_id}`);
            return await waitForTask(data.task_id);
        }

        return data;
    }

    async function switchProxyBeforeRetry(account, retryNumber, maxRetries) {
        const reason = `第 ${account.line_number} 行页面加载失败，正在切换代理后重试 (${retryNumber}/${maxRetries})`;
        setAccountStatus(reason, 'warning');
        appendLog(reason);

        const generatedUrl = await generateAndSaveProxy({ auto: true });
        if (!generatedUrl) {
            appendLog('切换代理失败，无法重试当前账号');
            return false;
        }

        appendLog(`代理已切换，准备重新处理第 ${account.line_number} 行账号`);
        return true;
    }

    async function refreshCredentialManagementState() {
        try {
            const response = await fetch('./config/get', { headers: getAuthHeaderValues() });
            const data = await response.json();
            if (response.ok && typeof AppState !== 'undefined') {
                AppState.currentConfig = data.config || {};
                AppState.envLockedFields = new Set(data.env_locked || []);
                AppState.proxyPoolLoaded = true;
                if (typeof refreshProxyPoolBindingsFromCredentialStatus === 'function') {
                    await refreshProxyPoolBindingsFromCredentialStatus();
                }
            }
        } catch (error) {
            appendLog(`静默刷新代理池配置失败: ${error.message}`);
        }

        if (typeof AppState !== 'undefined' && AppState.creds && typeof AppState.creds.refresh === 'function') {
            try {
                await AppState.creds.refresh();
            } catch (error) {
                appendLog(`静默刷新GCLI凭证管理失败: ${error.message}`);
            }
        }
    }

    async function loadExistingCredentialEmails() {
        const emails = new Set();
        let offset = 0;
        const limit = 1000;
        let guard = 0;

        while (guard < 50) {
            guard += 1;
            const response = await fetch(
                `./creds/status?offset=${offset}&limit=${limit}&status_filter=all&error_code_filter=all&cooldown_filter=all&preview_filter=all&tier_filter=all&mode=geminicli`,
                { headers: getAuthHeaderValues() }
            );
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.detail || data.error || '加载GCLI凭证管理邮箱失败');
            }

            (data.items || []).forEach(item => {
                const email = normalizeEmail(item.user_email);
                if (email) emails.add(email);
            });

            if (!data.has_more) break;
            offset += data.limit || limit;
        }

        return emails;
    }

    async function processAccounts(accounts) {
        state.accounts = accounts;
        state.failedAccounts = [];
        state.isBatchRunning = true;
        setStartButtonDisabled(true);

        let unusableCount = 0;
        let failedCount = 0;
        let savedCount = 0;
        let saveSkippedCount = 0;
        let skippedCount = 0;

        try {
            appendLog('正在查询 GCLI凭证管理 中已存在的邮箱...');
            state.existingCredentialEmails = await loadExistingCredentialEmails();
            appendLog(`已加载 ${state.existingCredentialEmails.size} 个已有邮箱，用于跳过重复账号`);

            for (let index = 0; index < accounts.length; index += 1) {
                if (!state.isBatchRunning) break;

                const account = accounts[index];
                const normalizedEmail = normalizeEmail(account.email);
                if (normalizedEmail && state.existingCredentialEmails.has(normalizedEmail)) {
                    skippedCount += 1;
                    const skippedMessage = `第 ${account.line_number} 行账号 ${account.email} 已存在于 GCLI凭证管理，跳过`;
                    setAccountStatus(skippedMessage, 'warning');
                    appendLog(skippedMessage);
                    continue;
                }

                setAccountStatus(`正在处理第 ${index + 1}/${accounts.length} 行账号：${account.email}`, 'info');
                appendLog(`开始处理第 ${index + 1}/${accounts.length} 行账号: ${account.email}`);
                appendLog(
                    `第 ${account.line_number} 行字段: 密码=已提供, 2FA=${account.two_fa_key ? '已提供' : '未提供'}, ` +
                    `手机号=${account.phone ? '已提供' : '未提供'}, 手机验证码链接=${account.phone_code_url ? '已提供' : '未提供'}`
                );

                try {
                    let taskResult = null;
                    const maxProxyRetries = 1;
                    for (let attempt = 0; attempt <= maxProxyRetries; attempt += 1) {
                        taskResult = await submitAccount(account, index, accounts.length);
                        if (
                            taskResult &&
                            taskResult.status === 'failed' &&
                            isPageLoadFailure(taskResult) &&
                            attempt < maxProxyRetries
                        ) {
                            const switched = await switchProxyBeforeRetry(account, attempt + 1, maxProxyRetries);
                            if (switched) continue;
                        }
                        break;
                    }

                    if (taskResult.account_unusable || taskResult.status === 'unusable') {
                        unusableCount += 1;
                        const failureReason = String(taskResult.failure_reason || '账号不可用').trim();
                        const reasonText = formatFailureReason(failureReason);
                        recordFailedAccount(account, failureReason);
                        const message = failureReason === 'phone_rate_limited'
                            ? `第 ${account.line_number} 行账号 ${account.email} 当前手机号异常，已关闭无痕Chrome，继续处理下一行`
                            : (failureReason === 'service_unavailable'
                                ? `第 ${account.line_number} 行账号 ${account.email} 页面提示 Entire service unavailable，已关闭无痕Chrome，继续处理下一行`
                                : `第 ${account.line_number} 行账号 ${account.email} 不可用（${reasonText}），已关闭无痕Chrome，继续处理下一行`);
                        setAccountStatus(message, 'error');
                        appendLog(message);
                        continue;
                    }

                    if (taskResult.status === 'completed') {
                        const credentialPersisted = Boolean(taskResult.credential_persisted || taskResult.saved_credential_filename);
                        const finalTestStatusCode = getFinalTestStatusCode(taskResult);
                        if (credentialPersisted) {
                            savedCount += 1;
                            const savedEmail = normalizeEmail(taskResult.saved_user_email || account.email);
                            if (savedEmail) state.existingCredentialEmails.add(savedEmail);
                            await refreshCredentialManagementState();
                            const savedParts = [];
                            if (taskResult.saved_credential_filename) savedParts.push(`凭证=${taskResult.saved_credential_filename}`);
                            if (taskResult.saved_proxy_name) savedParts.push(`代理=${taskResult.saved_proxy_name}`);
                            if (taskResult.saved_preview_enabled) savedParts.push('Preview=ON');
                            if (taskResult.saved_user_email) savedParts.push(`邮箱=${taskResult.saved_user_email}`);
                            const savedSuffix = savedParts.length ? `，${savedParts.join('，')}` : '';
                            const completedMessage = `第 ${account.line_number} 行账号 ${account.email} 已处理完成${savedSuffix}`;
                            setAccountStatus(completedMessage, 'success');
                            appendLog(completedMessage);
                            continue;
                        }

                        saveSkippedCount += 1;
                        const skipReason = formatFailureReason(taskResult.save_skipped_reason || 'model_test_not_200');
                        const statusCodeText = finalTestStatusCode || '-';
                        const completedMessage =
                            `第 ${account.line_number} 行账号 ${account.email} 已完成验证和模型测试，` +
                            `但状态码为 ${statusCodeText}，${skipReason}`;
                        setAccountStatus(completedMessage, 'warning');
                        appendLog(completedMessage);
                        continue;
                    }

                    failedCount += 1;
                    const reason = formatFailureReason(taskResult.failure_reason || taskResult.error || '处理失败');
                    recordFailedAccount(account, reason);
                    const message = `第 ${account.line_number} 行账号 ${account.email} 处理失败，原因: ${reason}，继续处理下一行`;
                    setAccountStatus(message, 'warning');
                    appendLog(message);
                } catch (error) {
                    failedCount += 1;
                    const reason = error.message || '启动失败';
                    recordFailedAccount(account, reason);
                    const message = `第 ${account.line_number} 行账号 ${account.email} 启动失败: ${reason}`;
                    setAccountStatus(message, 'warning');
                    appendLog(`${message}，继续处理下一行`);
                }
            }

            const summary =
                `批量处理结束：保存成功 ${savedCount}，未入库 ${saveSkippedCount}，` +
                `跳过 ${skippedCount}，不可用 ${unusableCount}，失败 ${failedCount}，总计 ${accounts.length}`;
            const failedAccounts = formatFailedAccounts();
            const finalMessage = failedAccounts ? `${summary}\n失败邮箱：${failedAccounts}` : summary;
            setAccountStatus(finalMessage, unusableCount || failedCount || saveSkippedCount ? 'warning' : 'success');
            appendLog(summary);
            if (failedAccounts) appendLog(`失败邮箱：${failedAccounts}`);
            showStatus(
                finalMessage.replace(/\n/g, '；'),
                unusableCount || failedCount || saveSkippedCount ? 'warning' : 'success'
            );
        } finally {
            state.isBatchRunning = false;
            setStartButtonDisabled(false);
            state.activeTaskId = '';
            state.activeTaskDone = null;
        }
    }

    async function load() {
        updateProxyDisplay();

        try {
            const response = await fetch('./config/get', { headers: getAuthHeaderValues() });
            const data = await response.json();
            if (!response.ok) {
                showStatus(`加载凭证代理生成链接失败: ${data.detail || data.error || '未知错误'}`, 'error');
                return;
            }

            state.generatorUrl = data.config?.credential_proxy_generator_url || '';
            const savedProxyUrl = data.config?.[BATCH_PROXY_CONFIG_KEY] || '';
            const httpProxyUrl = toHttpProxyUrl(savedProxyUrl);
            state.currentProxyUrl = httpProxyUrl || state.currentProxyUrl || '';
            updateProxyDisplay();
            if (savedProxyUrl && httpProxyUrl && savedProxyUrl !== httpProxyUrl) {
                await saveBatchGenerateProxyUrl(httpProxyUrl);
            } else if (!state.currentProxyUrl) {
                await generateAndSaveProxy({ auto: true });
            }
        } catch (error) {
            showStatus(`加载凭证代理生成链接失败: ${error.message}`, 'error');
        }
    }

    async function switchProxy() {
        await generateAndSaveProxy();
    }

    function handleFileSelect(event) {
        const files = Array.from(event.target.files || []);
        if (files.length > 1) {
            showStatus('这里只能上传一个TXT文件', 'error');
            event.target.value = '';
            return;
        }

        if (files[0]) setFile(files[0]);
    }

    function handleFileDrop(event) {
        event.preventDefault();
        event.stopPropagation();

        const area = getElement('batchGenerateUploadArea');
        if (area) {
            area.style.borderColor = '';
            area.style.backgroundColor = '';
        }

        const files = Array.from(event.dataTransfer.files || []);
        if (files.length > 1) {
            showStatus('这里只能上传一个TXT文件', 'error');
            return;
        }

        if (files[0]) setFile(files[0]);
    }

    function handleDragOver(event) {
        event.preventDefault();
        const area = getElement('batchGenerateUploadArea');
        if (area) {
            area.style.borderColor = '#28a745';
            area.style.backgroundColor = '#e7f9e7';
        }
    }

    function handleDragLeave(event) {
        event.preventDefault();
        const area = getElement('batchGenerateUploadArea');
        if (area) {
            area.style.borderColor = '';
            area.style.backgroundColor = '';
        }
    }

    function clearFile() {
        stopLogPolling();
        state.isBatchRunning = false;
        state.activeTaskId = '';
        state.activeTaskDone = null;
        state.lastTaskLogSeq = 0;
        state.accounts = [];
        state.failedAccounts = [];
        state.selectedFile = null;
        const input = getElement('batchGenerateFileInput');
        if (input) input.value = '';
        updateFileList();
        setAccountStatus('');
    }

    function start() {
        stopLogPolling();
        state.activeTaskId = '';
        state.activeTaskDone = null;
        state.lastTaskLogSeq = 0;
        setAccountStatus('');

        if (!state.selectedFile) {
            showStatus('请先上传txt文件', 'error');
            appendLog('未选择txt文件，无法开始生成', true);
            return;
        }

        const reader = new FileReader();
        reader.onload = async function(event) {
            const text = String(event.target.result || '');
            const lines = text.split(/\r?\n/)
                .map(line => line.trim())
                .filter(Boolean);

            if (!lines.length) {
                showStatus('txt文件没有可用数据', 'error');
                appendLog('txt文件没有可用数据', true);
                return;
            }

            try {
                const accounts = [];
                appendLog(`读取到 ${lines.length} 行有效文本，开始解析账号`, true);
                lines.forEach((line, index) => {
                    try {
                        accounts.push(parseAccountLine(line, index + 1));
                    } catch (error) {
                        appendLog(`${error.message}，已跳过`);
                    }
                });

                if (!accounts.length) {
                    showStatus('txt文件没有可用账号数据', 'error');
                    setAccountStatus('txt文件没有可用账号数据', 'error');
                    return;
                }

                appendLog(`解析到 ${accounts.length} 个可用账号，将按行顺序逐个处理`);
                showStatus('已解析账号，开始按行处理', 'success');
                await processAccounts(accounts);
            } catch (error) {
                appendLog(`启动失败: ${error.message}`);
                setAccountStatus(`启动失败: ${error.message}`, 'error');
                showStatus(`启动失败: ${error.message}`, 'error');
            }
        };
        reader.onerror = function() {
            showStatus('读取txt文件失败', 'error');
            appendLog('读取txt文件失败', true);
        };
        reader.readAsText(state.selectedFile, 'utf-8');
    }

    window.BatchGenerate = {
        load,
        switchProxy,
        handleFileSelect,
        handleFileDrop,
        handleDragOver,
        handleDragLeave,
        clearFile,
        start
    };
})();
