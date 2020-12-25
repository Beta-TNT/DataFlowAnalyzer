import sys, os, base64
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import AnalyseLib

class AnalysePlugin(AnalyseLib.AnalyseBase.PluginBase):
    '切片比较插件'

    _ExtraRuleFields = {}
    _ExtraFieldMatchingRuleFields = {
        "SliceFrom": (
            "切片起始", 
            int
        ),
        "SliceTo": (
            "切片截止", 
            int
        )
    }
    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.splitext(os.path.basename(_PluginFilePath))[0]

    def LoadSetting(self):
        'dummy loadsetting func.'
        pass

    def AnalyseSingleData(self, InputData, InputRule):
        return self._AnalyseSingleData(InputData, InputRule)

    def _AnalyseSingleData(self, InputData, InputRule):
        '插件数据分析方法用户函数，接收被分析的dict()类型数据和规则作为参考数据，由用户函数判定是否满足规则。返回值定义同_DefaultSingleRuleTest()函数'
        # 切片比较插件
        # 在字段比较子规则里加入SliceFrom和SliceTo两个字段，整数，可为负,后者可以为None，实际上就是Python切片操作的前后两个参数
        # 由于内容性质，仅支持Equal/NotEqual和TextMatching/NotTextMatching两种比较运算
        # 运算结果会动态修改已输入的规则和数据。例如：
        # 输入字段切片比较规则（判断name字段内容最后3个字符是不是‘Doe’）：
        # {
        #    'FieldName': 'name',
        #    'MatchContent': 'Doe',
        #    'MatchCode': 1,
        #    'SliceFrom': -3,
        #    'SliceTo': None
        # }
        # 输入数据：
        # {'name': 'John Doe'}
        # 实际匹配运算内容：(InputData['name'][-3,] == 'Doe')
        # 在本例中，匹配结果是命中，于是在原数据中追加字段保存匹配结果：
        # {'name': 'John Doe', 'AnalyzerPluginSlicer_Result_0': True}
        # 最后改写当前切片匹配规则，使其变成原分析引擎可处理的普通规则：
        # {
        #    'FieldName': 'AnalyzerPluginSlicer_Result_0',
        #    'MatchContent': True,
        #    'MatchCode': 1
        # }
        # 这个机制可以推广到其他字段匹配插件

        fieldCheckList = InputRule.get('FieldCheckList')
        if fieldCheckList:
            i = 0
            for fieldCheckRule in filter(lambda x:'SliceFrom'in x and type(InputData.get(x['FieldName'])) in (str, bytes, bytearray), fieldCheckList):
                try:
                    targetData = InputData[fieldCheckRule['FieldName']][fieldCheckRule['SliceFrom']:fieldCheckRule.get('SliceTo')]
                    matchContent = fieldCheckRule['MatchContent']
                    matchResult = False
                    matchResultFieldName = '%s_Result_%s' % (self._CurrentPluginName, i)
                    if type(InputData[fieldCheckRule['FieldName']]) in (bytes, bytearray):
                        # 二进制
                        matchContent = base64.b64decode(matchContent)
                    
                    if abs(fieldCheckRule['MatchCode']) == AnalyseLib.AnalyseBase.MatchMode.Equal:
                        matchResult = (matchContent == targetData)
                    elif abs(fieldCheckRule['MatchCode']) == AnalyseLib.AnalyseBase.MatchMode.TextMatching:
                        if type(InputData[fieldCheckRule['FieldName']]) == str:
                            # 忽略大小写的文本匹配
                            targetData = targetData.lower()
                            matchContent = matchContent.lower()
                        matchResult = (targetData in matchContent)
                    else:
                        #忽略其他匹配类型
                        continue
                    # 将匹配结果写入原数据，新增匹配结果字段
                    InputData[matchResultFieldName] = ((fieldCheckRule['MatchCode'] < 0) ^ matchResult) # 负数代码结果取反，这个写法有点反直觉
                    # 最后修改规则，使其对应匹配结果真值字段
                    fieldCheckRule.pop('SliceFrom')
                    if 'SliceTo' in fieldCheckRule:
                        fieldCheckRule.pop('SliceTo')
                    fieldCheckRule['MatchContent'] = True # 其实也可以让Result一直为True，真正结果写到这个字段。但那就太反直觉了
                    fieldCheckRule['MatchCode'] = 1
                    fieldCheckRule['FieldName'] = matchResultFieldName
                    i += 1
                except:
                    continue
        rtn = super()._DefaultAnalyseSingleData(InputData, InputRule)
        return rtn

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "切片比较，仅支持相等比较和文本比较（包含）两种比较运算。对于二进制数据需要将比较内容写成Base64串。"

    @property
    def ExtraRuleFields(self):
        '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
        return self._ExtraRuleFields