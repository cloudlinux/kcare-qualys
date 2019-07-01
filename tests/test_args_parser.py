import mock

import kcare_qualys


def test_configfile(tmpdir):
    configfile = str(tmpdir.join('qualys.conf'))
    parser = kcare_qualys.parse_args(["-c", configfile, "fetch"])
    parser = kcare_qualys.parse_args(["-c", configfile, "patch"])
    parser = kcare_qualys.parse_args(["-c", configfile, "ignore"])
    assert parser.configfile == configfile


@mock.patch('kcare_qualys.setup_logging')
@mock.patch('kcare_qualys.configparser')
@mock.patch('kcare_qualys.qualysapi')
@mock.patch('kcare_qualys.patch')
def test_main(mock_patch, mock_qualys, mock_config, mock_logging):

    mock_config.ConfigParser().has_option.return_value = True
    mock_config.ConfigParser().get.return_value = 'test'
    with mock.patch('kcare_qualys.sys.argv', ['kcare_qualys', 'patch']):
        kcare_qualys.main()
        mock_patch.assert_called_once()

