(function ($, Backbone, _) {

    window.Template = {
        Model:  Backbone.Model.extend({}),

        View: Backbone.View.extend({
            initialize: function ($template, args) {
                this.template = _.template($($template).html());
                this.model.on('change', this.render, this);
                if (this.init)
                    this.init();
                if (args && args.render_on_init)
                    this.render();
            },

            render: function () {
                this.$el.html(this.template({}));
            },

            show: function () {
                this.$el.removeClass("hide");
            },

            hide: function () {
                this.$el.addClass("hide");
            },
        }),
    };

}) (jQuery, Backbone, _);
