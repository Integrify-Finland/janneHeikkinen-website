const path = require(`path`)
const WP_NODE = require("./src/utilities/blogs-node")

// Declared explicitly so the podcastit page query still works
// when there are no published podcasts in Contentful
exports.createSchemaCustomization = ({ actions }) => {
  actions.createTypes(`
    type ContentfulPodcast implements Node {
      topic: String
      podcastName: String
      host: String
      date: Date @dateformat
      url: String
    }
  `)
}

exports.createPages = ({ graphql, actions }) => {
  const { createPage } = actions
  // createRedirect({
  //   fromPath: `/vaalit`,
  //   toPath: `/`,
  //   isPermanent: true,
  //   redirectInBrowser: true,
  // })

  return graphql(`
    {
      allContentfulBlogPost {
        edges {
          node {
            id
            slug
          }
        }
      }
    }
  `).then(result => {
    result.data.allContentfulBlogPost.edges.forEach(({ node }) => {
      createPage({
        path: `blogi/${node.slug
          .toLowerCase()
          .replace(/[']/gi, "")
          .replace(/ /gi, "-")
          .replace(/[,]/gi, "")
          .replace(/[ä]/gi, "a")
          .replace(/[ö]/gi, "o")}`,
        component: path.resolve(`./src/templates/blogPost/index.js`),
        context: {
          slug: node.id,
        },
      })
    })
    WP_NODE.edges.forEach(({ node }) => {
      createPage({
        path: `blogi/${node.slug
          .toLowerCase()
          .replace(/[']/gi, "")
          .replace(/ /gi, "-")
          .replace(/[,]/gi, "")
          .replace(/[ä]/gi, "a")
          .replace(/[ö]/gi, "o")}`,
        component: path.resolve(`./src/templates/blogPost/index.js`),
        context: {
          slug: node.slug,
        },
      })
    })
  })
}
