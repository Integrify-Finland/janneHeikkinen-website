const path = require(`path`)
const WP_NODE = require("./src/utilities/blogs-node")

exports.createPages = ({ graphql, actions }) => {
  const { createPage } = actions

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
