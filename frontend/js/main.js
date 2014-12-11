(function ($, Backbone, _, Template, Forms) {
    $.urlParam = function (name) {
        var results = new RegExp('[\?&]' + name + '=([^&#]*)').exec(window.location.href);
        if (results == null) {
           return null;
        } else {
           return results[1] || 0;
        }
    };

    var Heading = {
        Model: Template.Model.extend({
            defaults: {
                title:      undefined,
                content:    undefined,
            },
        }),

        View: Template.View.extend({
            render: function () {
                this.$el.html(this.template({
                    head:       this.model.get('title'),
                    content:    this.model.get('content'),
                }));
            },
        }),
    };

    var Content = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({}),
    };

    var Error = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            show: function () {
                this.render();
                this.$el.removeClass("hide");
            },
        }),
    };

    var MainRouter = Backbone.Router.extend({
        routes: {
            '':                 'index',
            'index':            'index',
            'login':            'login',
            'register':         'register',
            'about':            'about',
            'about_:usr':       'about_usr',
            'messages':         'messages',
            'yammer':           'yammer',
            'yammer_data':      'yammer_data',

            'internal_error':   'internal_error',
            '*notFound':        'not_found',
        },

        initialize: function (options) {
            this._init_models(options.templates);
            this._init_views(options.templates);
            this.selectors = {};
        },

        _init_models: function (templates) {
            this.models = {
                heading: {
                    model:      new Heading.Model({
                        title:      'Hello',
                        content:    'Some content',
                    }),
                    el:         '.app-heading',
                    view_ref:   Heading.View,
                    template:   'heading_content',
                    args:       {
                        'render_on_init':   true,
                    },
                },

                general_content: {
                    model:      new Content.Model({}),
                    el:         '.app-content',
                    view_ref:   Content.View,
                    template:   'general_content',
                    args:       {
                        'render_on_init':   true,
                    },
                },

                login_form: {
                    model:      new Forms.Login.Model({}),
                    el:         '.app-login_form',
                    view_ref:   Forms.Login.View,
                    template:   'login_form',
                },

                yammer_form: {
                    model:      new Forms.Yammer.Model({}),
                    el:         '.app-yammer_form',
                    view_ref:   Forms.Yammer.View,
                    template:   'yammer_form',
                },

                yammer_data_form: {
                    model:      new Forms.YammerData.Model({}),
                    el:         '.app-yammer_data_form',
                    view_ref:   Forms.YammerData.View,
                    template:   'yammer_data_form',
                },

                user_info_form: {
                    model:      new Forms.UserInfo.Model({}),
                    el:         '.app-user_info_form',
                    view_ref:   Forms.UserInfo.View,
                    template:   'user_info_form',
                },

                cur_usr_info_form: {
                    model:      new Forms.CurUserInfo.Model({}),
                    el:         '.app-cur_usr_info_form',
                    view_ref:   Forms.CurUserInfo.View,
                    template:   'cur_usr_info_form',
                },

                messages_form: {
                    model:      new Forms.Messages.Model({}),
                    el:         '.app-messages_form',
                    view_ref:   Forms.Messages.View,
                    template:   'messages_form',
                },

                register_form: {
                    model:      new Forms.Register.Model({}),
                    el:         '.app-register_form',
                    view_ref:   Forms.Register.View,
                    template:   'register_form',
                },

                '404_err': {
                    model:      new Error.Model({}),
                    el:         '.app-404_err',
                    view_ref:   Error.View,
                    template:   '404_err',
                },

                '500_err': {
                    model:      new Error.Model({}),
                    el:         '.app-500_err',
                    view_ref:   Error.View,
                    template:   '500_err',
                },
            };
        },

        _init_views: function (templates) {
            var key, val;
            for (key in this.models) {
                val = this.models[key];
                val.view = new val.view_ref(_.extend({
                    el:     val.el,
                    model:  val.model,
                }, templates[val.template]), val.args);
            }
        },

        login: function () {
            this._change_current_nav_elem('Login');
            this._hide(['login_form']);
        },

        register: function () {
            this._change_current_nav_elem('Register');
            this._hide(['register_form']);
        },

        index: function () {
            this._change_current_nav_elem('Home');
            this._hide(['heading', 'general_content']);
        },

        about: function () {
            this._change_current_nav_elem('About');
            this._hide(['user_info_form']);
        },

        about_usr: function (usrname) {
            this.models.cur_usr_info_form.model.setUser(usrname);
            this._change_current_nav_elem('About');
            this._hide(['cur_user_info_form']);
        },

        messages: function () {
            this._change_current_nav_elem('Messages');
            this._hide(['messages_form']);
        },

        yammer: function () {
            this._change_current_nav_elem('Sign in with Yammer');
            this._hide(['yammer_form']);
        },

        yammer_data: function () {
            this._change_current_nav_elem('Get yammer data');
            this._hide(['yammer_data_form']);
        },

        not_found: function () {
            this._change_current_nav_elem('');
            this._hide(['404_err']);
        },

        internal_error: function () {
            this._change_current_nav_elem('');
            this._hide(['500_err']);
        },

        _hide: function (exceptions) {
            var key, val;
            for (key in this.models) {
                var val = this.models[key];
                val.view[_.indexOf(exceptions, key) >= 0 ? "show" : "hide"]();
            }
        },

        _change_current_nav_elem: function (new_title) {
            var $sel = this._get_selector('#main_menu');
            $sel.children().each(function (index, li) {
                var cond = li.innerText.trim().toUpperCase() == new_title.trim().toUpperCase();
                $(li)[cond ? 'addClass' : 'removeClass']('active');
            });
        },

        _get_selector: function (sel_name) {
            if (!this.selectors[sel_name]) {
                this.selectors[sel_name] = $(sel_name);
            }
            return this.selectors[sel_name];
        },
    });

    $(function () {
        var templates = {
            heading_content:    $('#src-heading_content'),
            general_content:    $('#src-general_content'),
            login_form:         $('#src-login_form'),
            register_form:      $('#src-register_form'),
            user_info_form:     $('#src-user_info'),
            cur_usr_info_form:  $('#src-cur_usr_info'),
            messages_form:      $('#src-messages'),
            yammer_form:        $('#src-yammer'),
            yammer_data_form:   $('#src-yammer_data'),
            '404_err':          $('#src-404_err'),
            '500_err':          $('#src-500_err'),
        };

        window.app = new MainRouter({
            templates: templates,
        });
        Backbone.history.start();
    });
}) ($, Backbone, _, window.Template, window.Forms);
