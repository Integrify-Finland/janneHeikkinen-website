require("dotenv").config()

module.exports = {
  siteMetadata: {
    title: `Janne Heikkinen`,
    description: `Janne Heikkinen website`,
    author: `Integrify`,
  },
  plugins: [
    `gatsby-transformer-remark`,
    {
      resolve: `gatsby-plugin-sass`,
      options: {
        data:
          '@import "_variables.scss";@import "_mixins.scss";@import "_layout.scss";',
        includePaths: ["src/assets/styles"],
      },
    },
    {
      resolve: `gatsby-source-youtube-v2`,
      options: {
        channelId: process.env.YOUTUBE_CHANNEL_ID,
        apiKey: process.env.YOUTUBE_API_KEY,
        maxVideos: 50, // Defaults to 50
      },
    },

    {
      resolve: `gatsby-source-filesystem`,
      options: {
        path: `${__dirname}/src/components/SocialMedia`,
        name: "SocialMedia",
      },
    },
    {
      resolve: `gatsby-transformer-remark`,
      options: {
        plugins: [
          {
            resolve: `@raae/gatsby-remark-oembed`,
            options: {
              // usePrefix defaults to false
              // usePrefix: true is the same as ["oembed"]
              usePrefix: false,
              providers: {
                include: ["Twitter", "Instagram", "Facebook"],
                settings: {
                  // Ex. Show all Twitter embeds with the dark theme
                  Twitter: { theme: "dark" },
                  // Ex. Hide all Instagram comments by default
                  Instagram: { hidecaption: true },
                },
                // Important to exclude providers
                // that adds js to the page.
                // If you do not need them.
                exclude: ["Reddit", "Flickr,"],
              },
            },
          },

          {
            resolve: `gatsby-remark-responsive-iframe`,
            options: {
              wrapperStyle: `margin-bottom: 1.0725rem`,
            },
          },
        ],
      },
    },

    {
      resolve: `gatsby-source-contentful`,
      options: {
        spaceId: process.env.CONTENTFUL_SPACE_ID,
        accessToken: process.env.CONTENTFUL_ACCESS_TOKEN,
      },
    },
    `gatsby-plugin-react-helmet`,
    {
      resolve: `gatsby-source-filesystem`,
      options: {
        name: `images`,
        path: `${__dirname}/src/images`,
      },
    },
    `gatsby-transformer-sharp`,
    `gatsby-plugin-sharp`,
    {
      resolve: `gatsby-plugin-manifest`,
      options: {
        name: `Janne Heikkinen`,
        short_name: `starter`,
        start_url: `/`,
        background_color: `#663399`,
        theme_color: `#663399`,
        display: `minimal-ui`,
        icon: `src/images/gatsby-icon.png`, // This path is relative to the root of the site.
      },
    },
    // {
    //   resolve: "gatsby-source-wordpress",
    //   options: {
    //     baseUrl: "http://www.janneheikkinen.fi",
    //     protocol: "http",
    //     hostingWPCOM: false,
    //     useACF: false,
    //     acfOptionPageIds: [],
    //     verboseOutput: false,
    //     perPage: 100,
    //     searchAndReplaceContentUrls: {
    //       sourceUrl: "http://www.janneheikkinen.fi/blogi/",
    //     },
    //     // Set how many simultaneous requests are sent at once.
    //     concurrentRequests: 10,
    //     // Set WP REST API routes whitelists
    //     // and blacklists using glob patterns.
    //     // Defaults to whitelist the routes shown
    //     // in the example below.
    //     // See: https://github.com/isaacs/minimatch
    //     // Example:  `["/*/*/comments", "/yoast/**"]`
    //     // ` will either include or exclude routes ending in `comments` and
    //     // all routes that begin with `yoast` from fetch.
    //     // Whitelisted routes using glob patterns
    //     includedRoutes: ["**/posts", "**/tags"],
    //   },
    // },
  ],
}
