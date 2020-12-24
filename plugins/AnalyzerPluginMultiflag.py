import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from AnalyseLib import AnalyseBase

class AnalysePlugin(AnalyseBase.PluginBase):
    _ExtraRuleFields = {
        "PrevFlags": (
            '前序Flag列表。如果规则也指定了PrevFlag字段，将会被纳入到这个列表',
            list
        ),
        "RemoveFlags": (
            '规则命中后待删除的Flag列表。如果规则也指定了RemoveFlag字段，将会被纳入这个列表',
            list
        ),
        "MultiFlagOperator": (
            '多个前序Flag命中逻辑关系。定义沿用字段逻辑匹配的OperatorCode',
            int,
            lambda x:x in (-2, -1, 1, 2),
            'Invaild MultiFlagOperator Code: %s, see OperatorCode defination for field check rule.'
        )
    }
    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.basename(_PluginFilePath).split('.')[:-1][0]

    def LoadSetting(self):
        pass

    def AnalyseSingleData(self, InputData, InputRule):
        return self._AnalyseSingleData(InputData, InputRule)

    def _AnalyseSingleData(self, InputData, InputRule):
        '数据分析方法接口，接收被分析的dict()类型数据和规则作为参考数据，应返回True/False'
        # 由于一次构造多个CurrentFlag需要修改算法底层逻辑
        # 退而求其次，用原规则逻辑构造1个CurrentFlag
        prevFlagsList   = InputRule.get('PrevFlags', list())
        removeFlagsList = InputRule.get('RemoveFlags', list())

        prevFlagsList.append(InputRule.get('PrevFlag'))
        removeFlagsList.append(InputRule.get('RemoveFlag'))

        rtn = (False, None)
        if len(set(prevFlagsList)) <= 1:
            InputRule['PrevFlag'] = list(set(prevFlagsList))[0]
            rtn = self._DefaultAnalyseSingleData(InputData, InputRule)
        else:            
            fieldCheckResult = False
            if type(InputRule["FieldCheckList"]) in (dict, list):
                fieldCheckResults = map(
                    lambda y:self._AnalyseBase.FieldCheck(InputData[y['FieldName']], y),
                    filter(
                        lambda x:x.get('FieldName') in InputData,
                        InputRule["FieldCheckList"]
                    )
                )
                if abs(InputRule["Operator"]) == self._AnalyseBase.OperatorCode.OpOr:
                    fieldCheckResult = any(fieldCheckResults)
                elif abs(InputRule["Operator"]) == self._AnalyseBase.OperatorCode.OpAnd:
                    fieldCheckResult = all(fieldCheckResults)

                fieldCheckResult = ((InputRule["Operator"] < 0) ^ fieldCheckResult) # 负数匹配代码结果取反
            else:
                # 字段匹配列表为空，直接判定字段匹配通过
                # Field check is None, ignore it.
                fieldCheckResult = True

            if not fieldCheckResult:
                rtn = (False, None)
            else:
                rtn = self.MultiPrevFlagCheck(
                    set(
                        map(
                            lambda x:self._AnalyseBase.FlagGenerator(
                                InputData,
                                x
                            ),
                            filter(
                                None,
                                prevFlagsList
                            )
                        )
                    ),
                    InputRule['MultiFlagOperator']
                )
        if rtn[0]:
            list(
                map(
                    self._AnalyseBase.RemoveFlag, 
                    set(
                        map(
                            lambda x:self._AnalyseBase.FlagGenerator(
                                InputData,
                                x
                            ),
                            filter(
                                None,
                                removeFlagsList
                            )
                        )
                    )
                )
            )
        return rtn

    def MultiPrevFlagCheck(self, InputPrevFlags, InputOperator):
        '多PrevFlag版FlagCheck函数，如果输入的多个PrevFlag按Operator，命中且仅命中了1个数据对象，则返回True, 命中的数据对象，否则返回False, None'
        flagCheckResults = list(map(self._AnalyseBase._DefaultFlagCheck, InputPrevFlags))
        hitResults = map(lambda x:x[0], flagCheckResults)
        # EventItem会命中多个
        hitEventItems = set(filter(None, map(lambda x:x[1], flagCheckResults)))
        if abs(InputOperator) == 1:
            hitResult = all(hitResults)
        elif abs(InputOperator) == 2:
            hitResult = any(hitResults)
        hitResult = ((InputOperator < 0) ^ hitResult)
        if hitResult:
            if InputOperator < 0:
                # 匹配代码为负数（取反），只要命中，无论命中了多少缓存，都返回True, None
                return (True, None)
            if len(hitEventItems) == 1:
                return (True, hitEventItems.pop())
                # 成功命中，返回命中的EventItem
            else:
                # 没有命中或者命中多个，返回False, None
                return (False, None)
        else:
            # 匹配失配，返回False, None
            return (False, None)

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "多Flag插件"