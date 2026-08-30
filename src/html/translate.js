/**
 * src/html/translate.js
 * Automatic UI Localization Engine for EdgeTunnel
 * Translates Dashboard, Settings, Tables, Maps, and Status to English
 */

export const uiTranslations = {
	// Header & Titles
	管理后台: 'Admin Dashboard',
	登录设置页面: 'Admin Login',
	'未设置 管理员密码': 'Admin Password Not Set',
	'未绑定 KV命名空间': 'KV Namespace Not Bound',
	'请设置 环境变量 为 ADMIN 的 管理员密码':
		'Please set the ADMIN environment variable with your admin password',
	'请绑定 变量名称 为 KV 的 KV命名空间': 'Please bind a KV namespace with variable name KV',
	'由 edgetunnel 强力驱动': 'Powered by EdgeTunnel',
	请输入管理员密码: 'Enter Admin Password',
	登录: 'Login',
	退出登录: 'Logout',
	退出: 'Logout',

	// Navigation Tabs & Sections
	订阅转换配置: 'Subconverter Config',
	优选订阅生成: 'Optimal Sub Generator',
	订阅转换: 'Subconverter',
	基础配置: 'Basic Config',
	代理配置: 'Proxy Config',
	反代配置: 'Reverse Proxy Config',
	节点信息: 'Node Information',
	节点列表: 'Node List',
	自定义节点: 'Custom Nodes',
	自定义优选: 'Custom Optimal IPs',
	自定义: 'Custom',
	路径模板: 'Path Templates',
	请求日志: 'Request Logs',
	日志查看: 'View Logs',
	使用统计: 'Usage Statistics',
	账号设置: 'Account Settings',
	系统设置: 'System Settings',
	帮助文档: 'Documentation',
	高级设置: 'Advanced Settings',
	安全检测: 'Security Detection',
	基本信息: 'Basic Info',
	地理位置: 'Geographic Location',
	运营商信息: 'ISP Information',
	风控评级: 'Risk Rating',

	// Action Buttons
	保存配置: 'Save Configuration',
	保存修改: 'Save Changes',
	保存并应用: 'Save & Apply',
	保存: 'Save',
	重置配置: 'Reset Config',
	重置为默认: 'Reset to Defaults',
	重置已选: 'Reset Selection',
	重置: 'Reset',
	取消选择: 'Deselect',
	取消: 'Cancel',
	确定: 'Confirm',
	确认选择: 'Confirm Selection',
	确认: 'Confirm',
	知道了: 'Got it',
	小时内不提示: 'Do not show for 24h',
	刷新: 'Refresh',
	刷新列表: 'Refresh List',
	复制: 'Copy',
	复制链接: 'Copy Link',
	复制成功: 'Copied Successfully',
	清除所有: 'Clear All',
	清除: 'Clear',
	清空日志: 'Clear Logs',
	测试连接: 'Test Connection',
	测试代理: 'Test Proxy',
	测试: 'Test',
	开始测速: 'Start Speed Test',
	测速: 'Speed Test',
	导出配置: 'Export Config',
	导入配置: 'Import Config',
	查看: 'View',
	下载: 'Download',
	二维码: 'QR Code',
	获取更多: 'Get More',
	添加: 'Add',
	删除: 'Delete',
	编辑: 'Edit',
	全选: 'Select All',
	反选: 'Invert Selection',

	// Status & Indicators
	启用全局代理: 'Enable Global Proxy',
	已启用全局代理: 'Global Proxy Enabled',
	启用: 'Enable',
	已启用: 'Enabled',
	关闭: 'Disable',
	已关闭: 'Disabled',
	禁用: 'Disabled',
	状态: 'Status',
	未知: 'Unknown',
	成功: 'Success',
	失败: 'Failed',
	错误: 'Error',
	警告: 'Warning',
	提示: 'Notice',
	'加载中...': 'Loading...',
	加载中: 'Loading',
	正在加载: 'Loading',
	'处理中...': 'Processing...',
	正在验证可用性: 'Verifying availability...',
	验证中: 'Verifying...',
	验证完成: 'Verification Complete',
	无数据: 'No Data',
	暂无数据: 'No Data Available',
	延迟: 'Latency',
	响应时间: 'Response Time',
	极度纯净: 'Very Clean',
	纯净: 'Clean',
	轻微风险: 'Low Risk',
	高风险: 'High Risk',
	极度危险: 'Very Dangerous',
	已超时: 'Timed Out',

	// Proxy & Protocol Terms
	传输协议: 'Transport Protocol',
	协议类型: 'Protocol Type',
	加密方式: 'Cipher Method',
	跳过证书验证: 'Skip Cert Verification',
	客户端指纹: 'Client Fingerprint',
	混淆方式: 'Obfuscation Method',
	混淆: 'Obfuscation',
	伪装域名: 'Camouflage Domain',
	伪装路径: 'Camouflage Path',
	反代: 'Reverse Proxy',
	全局代理: 'Global Proxy',
	全局: 'Global',
	标准: 'Standard',
	白名单: 'Whitelist',
	黑名单: 'Blacklist',
	优选域名: 'Optimal Domain',
	优选IP: 'Optimal IP',
	优选: 'Optimal',
	本地IP库: 'Local IP Database',
	本地: 'Local',
	随机IP数量: 'Random IP Count',
	指定端口: 'Specified Port',
	'更新时间（小时）': 'Update Interval (Hours)',
	更新时间: 'Update Interval',
	订阅更新时间: 'Subscription Update Interval',
	订阅名称: 'Subscription Name',
	订阅Token: 'Subscription Token',
	订阅地址: 'Subscription URL',
	订阅链接: 'Subscription Link',
	订阅: 'Subscription',
	国内直连: 'Direct (CN)',
	国内: 'Domestic',
	海外加速: 'Proxy (Global)',
	海外: 'Overseas',
	标准模式: 'Standard Mode',
	全局模式: 'Global Mode',
	规则模式: 'Rule Mode',
	直连模式: 'Direct Mode',
	分片大小: 'Fragment Size',
	分片间隔: 'Fragment Interval',
	分片: 'TLS Fragment',
	通知设置: 'Notification Settings',
	机器人Token: 'Bot Token',
	聊天ID: 'Chat ID',
	今日请求数: 'Today Requests',
	总请求数: 'Total Requests',
	配额上限: 'Quota Limit',
	剩余配额: 'Remaining Quota',
	使用量: 'Usage',
	流量: 'Traffic',
	密码: 'Password',
	协议: 'Protocol',
	域名: 'Domain',
	端口: 'Port',
	节点: 'Node',
	列表: 'List',
	配置: 'Config',
	地址: 'Address',
	地区: 'Region',
	大洲: 'Continent',
	国家: 'Country',
	城市: 'City',
	时区: 'Timezone',
	运营商: 'ISP',
	自治系统: 'Autonomous System (AS)',

	// Continents & Regions
	亚洲: 'Asia',
	北美洲: 'North America',
	北美: 'North America',
	欧洲: 'Europe',
	非洲: 'Africa',
	南美洲: 'South America',
	南美: 'South America',
	大洋洲: 'Oceania',
	南极洲: 'Antarctica',
	请选择地区: 'Select a Region',
	请选择代理: 'Select a Proxy',
	当前地区无可用代理: 'No available proxies in this region',
	请切换其他地区: 'Please switch to another region',

	// Hints & Messages
	请输入: 'Please enter ',
	选填: 'Optional',
	必填: 'Required',
	默认: 'Default',
	留空表示使用默认值: 'Leave empty for default value',
	每行一个: 'One per line',
	支持逗号或换行分隔: 'Supports comma or newline separation',
	修改成功: 'Modified successfully',
	保存成功: 'Saved successfully',
	操作成功: 'Operation successful',
	操作失败: 'Operation failed',
	'网络错误，请重试': 'Network error, please try again',
	域名不匹配提示: 'Domain Mismatch Notice',
	当前访问域名与配置不匹配: 'Current access domain does not match configured host',
};

export function translateHtml(html) {
	let translated = html;

	// Replace HTML lang tag to English
	translated = translated.replace(/lang=["']zh(-CN)?["']/gi, 'lang="en"');
	translated = translated.replace(
		/<title>管理后台<\/title>/gi,
		'<title>EdgeTunnel Admin Dashboard</title>'
	);
	translated = translated.replace(
		/<title>登录设置页面<\/title>/gi,
		'<title>EdgeTunnel Admin Login</title>'
	);

	// Replace known phrases in HTML (sorted by length descending to match full phrases first)
	const keys = Object.keys(uiTranslations).sort((a, b) => b.length - a.length);
	for (const key of keys) {
		const val = uiTranslations[key];
		translated = translated.replaceAll(key, val);
	}

	// Inject real-time DOM translation observer script
	const clientTranslator = `
<script>
(function() {
  const dict = ${JSON.stringify(uiTranslations)};
  const keys = Object.keys(dict).sort((a, b) => b.length - a.length);
  const regex = new RegExp(keys.map(k => k.replace(/[-\\/\\\\^$*+?.()|[\\]{}]/g, '\\\\$&')).join('|'), 'g');

  function translateNode(node) {
    if (!node) return;
    if (node.nodeType === 3) {
      if (node.nodeValue && regex.test(node.nodeValue)) {
        node.nodeValue = node.nodeValue.replace(regex, m => dict[m] || m);
      }
    } else if (node.nodeType === 1 && node.nodeName !== 'SCRIPT' && node.nodeName !== 'STYLE') {
      if (node.placeholder && regex.test(node.placeholder)) {
        node.placeholder = node.placeholder.replace(regex, m => dict[m] || m);
      }
      if (node.title && regex.test(node.title)) {
        node.title = node.title.replace(regex, m => dict[m] || m);
      }
      if (node.ariaLabel && regex.test(node.ariaLabel)) {
        node.ariaLabel = node.ariaLabel.replace(regex, m => dict[m] || m);
      }
      for (let i = 0; i < node.childNodes.length; i++) {
        translateNode(node.childNodes[i]);
      }
    }
  }

  function runTranslate() {
    if (document.body) translateNode(document.body);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runTranslate);
  } else {
    runTranslate();
  }

  try {
    const observer = new MutationObserver(mutations => {
      for (const m of mutations) {
        if (m.addedNodes) {
          for (let i = 0; i < m.addedNodes.length; i++) {
            translateNode(m.addedNodes[i]);
          }
        }
        if (m.type === 'characterData') {
          translateNode(m.target);
        }
      }
    });
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
      });
    }
  } catch (_) {}
})();
</script>
`;

	if (translated.includes('</body>')) {
		translated = translated.replace('</body>', clientTranslator + '</body>');
	} else {
		translated += clientTranslator;
	}

	return translated;
}
