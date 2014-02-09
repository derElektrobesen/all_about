(function ($, Backbone, _, Template, Forms) {
    var Heading = {
        Model: Template.Model.extend({
            defaults: {
                title:      undefined,
                content:    undefined,
            },
        }),

        View: Template.View.extend({
            init: function () {
                this.render();
            },

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
        View: Template.View.extend({
            init: function () {
                this.render();
            },

            render: function () {
                this.$el.html(this.template({}));
            },
        }),
    };

    var MainRouter = Backbone.Router.extend({
        routes: {
            '':                 'index',
            'index':            'index',
            'login':            'login',
            'register':         'register',
            'search/:query':    'search',
            'about':            'about',
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
                },

                general_content: {
                    model:      new Content.Model({}),
                    el:         '.app-content',
                    view_ref:   Content.View,
                    template:   'general_content',
                },

                login_form: {
                    model:      new Forms.Login.Model({}),
                    el:         '.app-login_form',
                    view_ref:   Forms.Login.View,
                    template:   'login_form',
                },

                register_form: {
                    model:      new Forms.Register.Model({}),
                    el:         '.app-register_form',
                    view_ref:   Forms.Register.View,
                    template:   'register_form',
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
                }, templates[val.template]));
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

        search: function (query) {
            // TODO
        },

        index: function () {
            this._hide(['heading', 'general_content']);
            this._change_current_nav_elem('Home');
        },

        about: function () {
            this._change_current_nav_elem('About');
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
        };

        window.app = new MainRouter({
            templates: templates,
        });
        Backbone.history.start();
    });
}) ($, Backbone, _, window.Template, window.Forms);
