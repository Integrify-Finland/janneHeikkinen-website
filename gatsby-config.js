require("dotenv").config()

module.exports = {
  siteMetadata: {
    title: `Janne Heikkinen`,
    description: `Janne Heikkinen website`,
    author: `Integrify`,
  },
  plugins: [
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
      channelId: ['UCnwzt3vtqtYyRMIpVf-EFLg'],
      apiKey: '<< Add your Youtube api key here>>',
      maxVideos: 50 // Defaults to 50
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
    // this (optional) plugin enables Progressive Web App + Offline functionality
    // To learn more, visit: https://gatsby.dev/offline
    // `gatsby-plugin-offline`,
  ],
}
