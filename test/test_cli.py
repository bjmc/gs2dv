

from gs2dvlib.cli import standard_database_user, get_siteid

def test_get_siteid():
    assert get_siteid('s1235.gridserver.com') == '1235'
    assert get_siteid('s1.gridserver.com') == '1'
    assert get_siteid('s12.gridserver.com') == '12'
    assert get_siteid('s123.gridserver.com') == '123'
    assert get_siteid('1235.gridserver.com') == None
    assert get_siteid('x1235.gridserver.com') == None

def test_standard_database_user():
    assert standard_database_user('db12') == None
    assert standard_database_user('db123') == True
    assert standard_database_user('db12345') == True
    assert standard_database_user('db12345') == True
    assert standard_database_user('saldkfjlkj') == None
    assert standard_database_user('2345') == None


