
import kcare_qualys


def test_configfile(tmpdir):
    configfile = str(tmpdir.join('qualys.conf'))
    parser = kcare_qualys.parse_args(["-c", configfile, "fetch"])
    parser = kcare_qualys.parse_args(["-c", configfile, "patch"])
    parser = kcare_qualys.parse_args(["-c", configfile, "ignore"])
    assert parser.configfile == configfile
