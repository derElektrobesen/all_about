(function ($, Backbone, _, Template) {

    var user_info_model_ptr = undefined;
    var messages_model_ptr = undefined;

    var Login = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.$el.on('submit', 'form', this.apply, this);
            },

            apply: function (form_ref, e) {
                var $form = $(form_ref),
                    $passw = $form.find("#edt_passw"),
                    $login = $form.find("#edt_login"),
                    login = $login.val(),
                    passw = $passw.val(),
                    remember = $form.find("#chb_remember").prop("checked"),
                    class_name = "has-error",
                    $err = $form.find("#login-error_message");
                $err.addClass("hide");
                if (!login || !passw) {
                    $err.removeClass("hide");
                    $passw.val('');
                } else {
                    var self = this,
                        callback = function (data) {
                            $passw.val('');
                            if (data && data.responseText) try {
                                return self.set_err_message("Incorrect username or password");
                            } catch(e) { } // Internal error
                            return self.set_err_message("Internal server error");
                        };
                    $err.addClass("hide");
                    var general_login = {
                        method:     'POST',
                        dataType:   'json',
                        error:      callback,
                        statusCode: {
                            404:    callback,
                            400:    callback,
                        },
                        xhrFields: {
                            withCredentials: true
                        },
                    };

                    var auth_code = $.urlParam('oauth');
                    if (auth_code != null) {
                        var data = $.param({ client_id: $.urlParam('client_id'), grant_type: 'password' });
                        $.extend(general_login, {
                            url:        'https://oauth.allabout/oauth_login?' + data,
                            method:     'GET',
                            headers: {
                                'Authorization': 'Basic ' + btoa(login + ':' + passw),
                            },
                            success: function (data) {
                                if (data['redirect_to']) {
                                    $(location).attr('href', data['redirect_to']);
                                }
                            },
                        });
                    } else {
                        $.extend(general_login, {
                            url:        '/cgi-bin/login.cgi',
                            headers: {
                                'Access-Control-Allow-Origin': '*',
                            },
                            data:       {
                                login:      login,
                                passw:      passw,      // SSL is needed
                                remember:   remember,
                            },
                            success:    function (data) {
                                user_info_model_ptr.request_data(true);
                            },
                        });
                    }
                    console.log(general_login);
                    $.ajax(general_login);
                }
                e[0].preventDefault();
                return true;
            },

            set_err_message: function (message) {
                var $el = this.$el.find("#login-error_message");
                $el.html("<strong>Error!</strong>&nbsp;" + message).removeClass("hide");
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
            },
        }),
    };

    var Register = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.$el.on('submit', 'form', this.apply, this);
            },

            apply: function (form_ref, e) {
                var $form = $(form_ref),
                    edits_names = {
                        'edt_username':     'username',
                        'edt_email':        'email',
                        'edt_real_name':    'name',
                        'edt_surname':      'surname',
                        'edt_lastname':     'lastname',
                        'edt_passw':        'passw',
                    },
                    $grp_p = $form.find("#grp_passw"),
                    $grp_p_a = $form.find("#grp_passw_a"),
                    $edt_passw = $grp_p.find("#edt_passw"),
                    $edt_passw_a = $grp_p_a.find("#edt_passw_a");

                $form.find("#register-error_message").addClass("hide");
                $grp_p.removeClass("has-error");
                $grp_p_a.removeClass("has-error");

                if ($edt_passw.val() != $edt_passw_a.val()) {
                    this.set_err_message("Passwords are not equal");
                    $grp_p.addClass("has-error");
                    $grp_p_a.addClass("has-error");
                    $edt_passw.val('');
                    $edt_passw_a.val('');
                } else {
                    var data = {},
                        self = this,
                        callback = function (data) {
                            $grp_p.removeClass("has-error");
                            $grp_p_a.removeClass("has-error");
                            $edt_passw.val('');
                            $edt_passw_a.val('');
                            if (data && data.responseText) try {
                                return self.set_err_message(JSON.parse(data.responseText).error);
                            } catch(e) { } // Internal error
                            return self.set_err_message("Internal server error");
                        };
                    _.keys(edits_names).forEach(function (entry) {
                        var val = $form.find("#" + entry).val();
                        if (val)
                            data[edits_names[entry]] = val;
                    });
                    $.ajax({
                        url:        '/cgi-bin/register.cgi',
                        method:     'POST',
                        dataType:   'json',
                        data:       data,
                        success:    function (data) {
                            user_info_model_ptr.request_data(true);
                        },
                        error:      callback,
                        statusCode: {
                            404:    callback,
                            400:    callback,
                        },
                    });
                }
                e[0].preventDefault();
                return true;
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
            },

            set_err_message: function (message) {
                var $el = this.$el.find("#register-error_message");
                $el.html("<strong>Error!</strong>&nbsp;" + message).removeClass("hide");
            },
        }),
    };

    var Yammer = {
        Model: Template.Model.extend({
            request_access: function () {
                $.ajax({
                    method: 'GET',
                    url: '/cgi-bin/yammer_auth.cgi',
                    success: function (data) {
                        if (data['redirect_to']) {
                            $(location).attr('href', data['redirect_to']);
                        } else {
                            alert("Already logged in");
                        }
                    },
                });
            },
        }),
        View: Template.View.extend({
            show: function () {
                this.model.request_access();
            },
        }),
    };

    var YammerData = {
        Model: Template.Model.extend({
            request_data: function (obj, callback) {
                $.ajax({
                    method: 'GET',
                    url: '/cgi-bin/get_yammer_data.cgi',
                    success: function (data) {
                        callback(obj, data);
                    },
                error: function (xhr) {
                    if (xhr.status === 401)
                        alert("Need to be logged in with yammer");
                },
                });
            },
        }),
        View: Template.View.extend({
            render: function (self, data) {
                self.$el.html(self.template({ src: data }));
                self.$el.removeClass('hide');
            },

            show: function () {
                this.model.request_data(this, this.render);
            },
        }),
    };

    var CurUserInfo = {
        Model: Template.Model.extend({
            defaults: {
                logged_in:          false,
                error:              undefined,
                username:           undefined,
                email:              undefined,
                name:               undefined,
                surname:            undefined,
                lastname:           undefined,
            },

            setUser: function (usrname) {
                this.get_user_info(usrname);
            },

            get_user_info: function (usrname) {
                var self = this;
                this.set({ logged_in: false }, { silent: true });
                $.ajax({
                    url:            '/cgi-bin/get_user_info.cgi',
                    data: {
                        username:    usrname,
                    },
                    success:        function (data) {
                        if (data.error) {
                            self.set({
                                logged_in: true,
                                error: data.error,
                            });
                        } else {
                            self.set({
                                logged_in: true,
                                username: data.login,
                                email: data.email,
                                name: data.name,
                                surname: data.surname,
                                lastname: data.lastname,
                            });
                        }
                        window.Forms.ShowTabs(true);
                    },
                    error:          function () {
                        self.set({ logged_in: true }, { silent: true });
                        self.set({ logged_in: false });
                        window.Forms.ShowTabs(false);
                    },
                });
            },
        }),

        View: Template.View.extend({
            init: function () {
                this.$el.on('click', '#btn_logout', this.logout);
            },

            render: function () {
                this.$el.html(this.template({
                    logged_in:      this.model.get('logged_in'),
                    username:       this.model.get('username'),
                    email:          this.model.get('email'),
                    name:           this.model.get('name'),
                    surname:        this.model.get('surname'),
                    lastname:       this.model.get('lastname'),
                    error:          this.model.get('error'),
                }));
                this.$el.removeClass('hide');
            },

            show: function () {
                this.render();
            },

            hide: function () {
                this.$el.addClass("hide");
            },

            logout: function () {
                var self = this;
                $.ajax({
                    url:            '/cgi-bin/logout.cgi',
                    success:        function () {
                        $(".login_tab").show();
                        $(".logged_in").hide();
                        window.app.navigate("#", true);
                        if (user_info_model_ptr)
                            user_info_model_ptr.set({
                                logged_in:          false,
                            });
                        if (messages_model_ptr)
                            messages_model_ptr.set({
                                logged_in:          false,
                            });
                    },
                });
            },
        }),
    };

    var UserInfo = {
        Model: Template.Model.extend({
            defaults: {
                logged_in:          false,
                data:               undefined,
            },

            initialize: function () {
                user_info_model_ptr = this;
                this.request_data(false);
            },

            request_data: function (make_redirect) {
                var self = this;
                $.ajax({
                    url: '/cgi-bin/get_users_info.cgi?all=1',
                    success: function (data) {
                        self.set({ logged_in: data.logged_in, data: data });
                        if (data.logged_in) {
                            window.Forms.ShowTabs(true);
                            if (make_redirect)
                                window.app.navigate("#about", true);
                        } else {
                            window.Forms.ShowTabs(false);
                            if (make_redirect)
                                window.app.navigate("#about", true);
                        }
                    },
                    error: function () {
                        self.set({ logged_in: false, data: undefined });
                        window.Forms.ShowTabs(false);
                        if (make_redirect)
                            window.app.navigate("#about", true);
                    },
                });
            },
        }),

        View: Template.View.extend({
            init: function () {
                this.$el.on('click', '#btn_logout', this, this.logout);
            },

            render: function () {
                this.$el.html(this.template({
                    logged_in:      this.model.get('logged_in'),
                    data:           this.model.get('data'),
                }));
                if (window.location.href.match(/#about$/))
                    this.$el.removeClass('hide');
            },

            show: function () {
                this.render();
            },

            logout: function (event) {
                $.ajax({
                    url:            '/cgi-bin/logout.cgi',
                    success:        function () {
                        $(".login_tab").show();
                        $(".logged_in").hide();
                        event.data.model.request_data(false);
                        window.app.navigate("#", true);
                    },
                });
            },
        }),
    };

    var Messages = {
        Model: Template.Model.extend({
            defaults: {
                messages:         undefined,
                users:            undefined,
                current_user:     undefined,
                logged_in:        false,
            },

            initialize: function () {
                this._logged_in = false;
                this._messages_loaded = false;
                messages_model_ptr = this;
            },

            load_messages: function (callback, cur_user) {
                var self = this;
                this._messages_loaded = true;
                $.ajax({
                    url:            '/cgi-bin/check_messages.cgi',
                    success:        function (data) {
                        self._logged_in = true;
                        self.set({ messages: data.data, users: data.users, current_user: cur_user, logged_in: true });
                        if (callback)
                            callback(true);
                    },
                    error:          function () {
                        self.set({ logged_in: false, messages: undefined, users: undefined, cur_user: undefined });
                        if (callback)
                            callback(false);
                    },
                });
            },

            is_logged_in: function (callback) {
                if (this.get("logged_in") && !this._messages_loaded)
                    this.load_messages(callback);
                else if (callback)
                    callback(this._logged_in && this.get("logged_in"));
                return this._logged_in;
            },

            send_message: function (msg, to) {
                var self = this;
                $.ajax({
                    url:            '/cgi-bin/send_msg.cgi',
                    data:           {
                        'msg': msg,
                        'to': to,
                    },
                    success:        function () {
                        self.load_messages(undefined, to);
                    },
                });
            },
        }),

        View: Template.View.extend({
            init: function () {
                this._timer = -1;
                var self = this;
                this.$el.on('click', '#btn-send_message', function (e) { self.send_message(e, this); });
            },

            render: function () {
                var $el = this.$el,
                    self = this;
                this.model.is_logged_in(function (logged_in) {
                    $el.removeClass("hide");
                    $el.html(self.template({
                        logged_in:      logged_in,
                        messages:       self.model.get("messages"),
                        users:          self.model.get("users"),
                        current_user:   self.model.get("current_user"),
                    }));
                });
            },

            hide: function () {
                if (this._timer != -1)
                    clearInterval(this._timer);
                this._timer = -1;
                this.$el.addClass("hide");
            },

            show: function () {
                var self = this,
                    callback = function () {
                        if (self.model.is_logged_in() && self._timer == -1)
                            self._timer = setInterval(function () { self.model.load_messages(); }, 5000);
                    };
                this.model.load_messages(callback);
                this.render();
            },

            send_message: function (e, btn) {
                var $edt = this.$el.find("#edt-message"),
                    msg = $edt.val(),
                    to = this.$el.find("#sel-user").val(),
                    $err = this.$el.find("#sendmsg-error_message");
                if (to == "Select user") { // TODO: Set a constant
                    $err.html("<strong>Error!</strong> User is not selected.");
                    $err.show();
                    return;
                }

                $err.hide();
                if (msg.length) {
                    this.model.send_message(msg, to);
                    $edt.val("");
                }
            },
        }),
    };

    window.Forms = {
        Login: Login,
        Register: Register,
        UserInfo: UserInfo,
        CurUserInfo: CurUserInfo,
        Messages: Messages,
        Yammer: Yammer,
        YammerData: YammerData,

        ShowTabs: function (logged_in) {
            var to_show = logged_in ? ".logged_in" : ".login_tab",
                to_hide = logged_in ? ".login_tab" : ".logged_in";
            $(to_hide).hide();
            $(to_show).show();
        },
    };

}) (jQuery, Backbone, _, window.Template);
