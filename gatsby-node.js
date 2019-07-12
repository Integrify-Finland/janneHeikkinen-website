const path = require(`path`)

exports.createPages = ({ graphql, actions }) => {
  const { createPage, createRedirect } = actions
  createRedirect({
    fromPath: "/",
    toPath: "/fi/",
    isPermanent: true,
    redirectInBrowser: true,
  })
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
      allWordpressPost {
        edges {
          node {
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
    result.data.allWordpressPost.edges.forEach(({ node }) => {
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
