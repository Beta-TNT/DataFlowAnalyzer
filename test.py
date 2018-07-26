import AnalyseLib

FieldRuleA1 = {
    'FieldName': 'abc',
    'MatchContent': 123,
    'MatchCode': 1,
}

FieldRuleA2 = {
    'FieldName': 'xyz',
    'MatchContent': 456,
    'MatchCode': 1,
}

rule1 = {
    'Operator': 0,
    'PrevFlag': '',
    'CurrentFlag': 'test1:{test}',
    'FlagThrehold': 1,
    'FlagLifetime': 1,
    'FieldCheckList': [FieldRuleA1, FieldRuleA2]
}

FieldRuleB1 = {
    'FieldName': 'abc',
    'MatchContent': 789,
    'MatchCode': 1,
}

FieldRuleB2 = {
    'FieldName': 'xyz',
    'MatchContent': 1024,
    'MatchCode': 1,
}

rule2 = {
    'Operator': 1,
    'PrevFlag': 'test1:{test}',
    'CurrentFlag': 'test2:{test}',
    'FlagThrehold': 1,
    'FlagLifetime': 1,
    'FieldCheckList': [FieldRuleB1, FieldRuleB2]
}

rules = [rule1, rule2]

testData1 = {
    'abc': 123,
    'xyz': 456,
    'test': 'test1'
}

testData2 = {
    'abc': 789,
    'xyz': 1024,
    'test': 'test1'
}

testData3 = {
    'abc': 789,
    'xyz': 1024,
    'test': 'test1'
}


def check(InputData, Rule, HitItem, CurrentFlag):
    return 'success!'


if __name__ == '__main__':
    
    testAnalyse = AnalyseLib.AnalyseBase(rules)
    testAnalyse.AnalyseMain(testData1, check) # hit rule1, generate new cache obj with 1 threhold and 1 lifetime
    testAnalyse.AnalyseMain(testData2, check) # hit the cache obj which rule1 generated, but the threhold prevent it from hit
    testAnalyse.AnalyseMain(testData2, check) # hit the cache obj again, this time the threhold is comsumed and the cache is vaild
    testAnalyse.AnalyseMain(testData3, check) 
    testAnalyse.AnalyseMain(testData3, check)
