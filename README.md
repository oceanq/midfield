#基于nginx的web代理

+ ngx_http_permit_module
	- 用于检测访问是否被允许
	- 使用nginx hash完成*域名的匹配，*只能位于第一个域名或最后一个域名
	- 包含命令举例如下:
		- portal_allow usergroup url:允许usergroup访问url
		- portal_deny usergroup url:拒绝usergroup访问url
		- portal_url user url:只允许user访问url
		- portal_default on/off:默认访问权限

+ ngx_http_html_filter_module
	- 将所有chunk缓存到一个大buf里，对该buf进行处理
	- 结合header和buf特点检测类型
	- html使用libxml2进行解析，StartElement完成属性处理，EndElement完成text处理
	- js/css分别使用正则表达式进行解析处理，js处理中将所有可能包含url的可能分为函数和赋值两种，替换成各自对应的js函数，在js函数中完成判断替换（更为统一）
	- header中的处理目前仅包含cookie的修改，用户server的cookie校验。

+ 其他修改
	- 添加自定义变量,根据转换后的path部分进行解析，获取被代理部分的对应属性
		- sslvpn_host:host
		- sslvpn_hostname: hostname
		- sslvpn_path: path
		- sslvpn_url:  url

+ url编码
	- 仅对字母进行映射替换
	- 仅对path部分进行编码，（http://10.2.3.137:10443/sslvpn/http/ehr.neusoft.com/ehzbgbgwxq.wh）

+ ** 待解决问题  **
	- ** 需要对gzip进行解析处理 **
	- ** 类型检测需要确定是否准确，看是否有其他方案（可以尝试借由html标签/属性确定类型,但在js和css中的请求可能无法处理1） **
	- ** 内存占用情况确定 **
	- ** js替换调试 **


+ ** 进行中问题 **
	+ 类型识别处理
		- 根据标签属性确定类型，并缓存文件名（全路径,只关注js和css即可，否则默认为html）
		- 收到应答时，查询列表，没有则原方案处理
	+ 权限处理（结合具体需求）
	+ 私有应用问题


==============================================================================












	