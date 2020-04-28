

if __name__ == "__main__": # TODO
    # Test with
    # python3 vreauthenticator.py <username> <token> <url>

    import sys
    if not len(sys.argv) >= 3:
        print('Not enough args, please call like this: "python 3 vreauthenticator.py <username> <token> <url>"')
        exit(1)

    logging.basicConfig()

    username=sys.argv[1]
    token=sys.argv[2]
    url=sys.argv[3]

    print('__________________________\nTest Authentication...')

    print(check_token_at_dashboard(token, url))

    print('__________________________\nTest creating an Authenticator object...')

    wda = VREAuthenticator()

    print('__________________________\nTest the object...')

    handler = None
    data = dict(
        username = username,
        password = password,
        webdav_url = url,
        webdav_password = password,
        webdav_mountpoint = 'fumptz'
    )

    res = wda.authenticate(handler, data)
    if res.done():
        res = res.result()

    print('__________________________\nTest pre-spawn...')
    try:
        os.mkdir('/tmp/mytest/')
        os.mkdir('/tmp/mytest/myuser')
    except Exception as e:
        print(e)
        pass

    import mock
    user = mock.MagicMock()
    user.get_auth_state.return_value = res['auth_state']
    spawner = mock.MagicMock()
    spawner.volume_binds = {'/tmp/mytest/myuser' : {'bind': '/path/in/spawned/container', 'mode': 'rw'}}
    spawner.volume_mount_points = ['/path/in/spawned/container']
    wda.pre_spawn_start(user, spawner)


