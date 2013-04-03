YUI.add('moodle-auth_persona-persona', function (Y) {
    var SELECTORS = {
        LOGINBUTTON:  '.auth-persona-loginbtn',
        LOGOUTBUTTON: '.logininfo .logout',
        LOGINFORM:    'form#login',
    };

    var currentUser;
    var loginform;

    M.auth_persona = {
        init: function(config) {
            if (config && config.user) {
                currentUser = config.user;
            } else {
                currentUser = null;
            }
            Y.delegate('click', this.handlelogin, Y.config.doc, SELECTORS.LOGINBUTTON, this);
            Y.delegate('click', this.handlelogout, Y.config.doc, SELECTORS.LOGOUTBUTTON, this);
            loginform = Y.one(SELECTORS.LOGINFORM);
            navigator.id.watch({
                loggedInUser: currentUser,
                onlogin: function(assertion) {
                    if (loginform) {
                        var assertionNode = Y.Node.create('<input type="hidden" name="personaassertion" value="'+assertion+'" />');
                        loginform.append(assertionNode);
                        loginform.submit();
                    }
                },
                onlogout: function() {
                    Y.config.win.location = M.cfg.wwwroot+'/login/logout.php?sesskey='+M.cfg.sesskey;
                },
            });
        },
        handlelogin: function(e) {
            e.preventDefault();
            navigator.id.request();
        },
        handlelogout: function(e) {
            e.preventDefault();
            navigator.id.logout();
        },
    };
}, '@VERSION@', {requires: ['node', 'external-persona']});
