import React from "react"
import { graphql } from "gatsby"
import Helmet from "react-helmet"
import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import BlogPost from "../../components/BlogPost"
import Section from "../../components/Section"

import { selectImg } from "../../utilities/WPImages"
import { formatDate } from "../../utilities/FormatDate"
import { WPContent, WP } from "../../utilities/WPblogs.js"
import { switchToCat } from "../../utilities/switches"

const BlogPostTemplate = ({ data, location }) => {
  const { allContentfulBlog, contentfulBlog } = data

  const allPosts = [...allContentfulBlog.edges, ...WPContent.edges, ...WP.edges]

  const allSlugs = allPosts.map(({ node }) => {
    return node.slug
  })

  const currentBlog = WPContent.edges
    .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
    .map(blog => blog.node)[0]

  const currentCat =
    currentBlog && WP.edges
      ? switchToCat(
          WP.edges
            .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
            .filter(({ node }) => node.categories !== null)
            .map(blog => blog.node.categories)[0][0]
        )
      : "No categories"

  const currentTags =
    currentBlog && WP.edges
      ? WP.edges
          .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
          .filter(({ node }) => node.tags !== null)
          .map(blog => blog.node.tags.map(tag => " " + tag.name))
      : "No tags"

  const renderBlogPost = () => {
    return { __html: contentfulBlog.body.childMarkdownRemark.html }
  }
  const createMarkup = () => {
    return { __html: currentBlog.content }
  }

  const date = currentBlog
    ? formatDate(currentBlog.date)
    : formatDate(contentfulBlog.date)
  return (
    <Layout>
      {contentfulBlog && (
        <Helmet>
          <meta property="og:title" content={contentfulBlog.title} />

          <meta
            name="og:description"
            property="og:description"
            content={contentfulBlog.description}
          />
          <meta name="twitter:title" content={contentfulBlog.title} />
          {/* <meta name="twitter:description" content={contentfulBlog.description} /> */}
          <meta name="twitter:card" content="summary_large_image" />
          <meta
            name="twitter:image:src"
            content={`https:${contentfulBlog.entryImage.fluid.src}`}
          />
          <meta
            name="twitter:image"
            content={`https:${contentfulBlog.entryImage.fluid.src}`}
          />
        </Helmet>
      )}
      {currentBlog && (
        <Helmet>
          <meta property="og:title" content={currentBlog.title} />
          <meta
            name="og:image"
            property="og:image"
            content={selectImg(currentBlog.id)}
          />
          {/* <meta
                name="og:description"
                property="og:description"
                content={description}
              /> */}
          <meta name="twitter:title" content={currentBlog.title} />
          {/* <meta name="twitter:description" content={description} /> */}
          <meta name="twitter:card" content="summary_large_image" />
          <meta name="twitter:image:src" content={selectImg(currentBlog.id)} />
          <meta name="twitter:image" content={selectImg(currentBlog.id)} />
        </Helmet>
      )}

      <div style={{ paddingTop: "128px", backgroundColor: "#edf5f8" }}>
        <SEO title="blogi" />
        <Section isBlog>
          {contentfulBlog && (
            <BlogPost
              isFluid={!!contentfulBlog.entryImage}
              date={date}
              title={contentfulBlog.title}
              image={contentfulBlog.entryImage}
              tags={contentfulBlog.tags}
              categories={contentfulBlog.categories}
              slug={contentfulBlog.slug}
              allSlugs={allSlugs}
            >
              <div
                className="blog-post"
                dangerouslySetInnerHTML={renderBlogPost()}
              ></div>
            </BlogPost>
          )}
        </Section>
        <Section>
          {currentBlog && (
            <BlogPost
              isFluid={false}
              date={date}
              title={currentBlog.title}
              image={selectImg(currentBlog.id)}
              categories={currentCat}
              tags={currentTags}
              slug={currentBlog.slug}
              allSlugs={allSlugs}
            >
              <div
                className="blog-post"
                dangerouslySetInnerHTML={createMarkup()}
              ></div>
            </BlogPost>
          )}
        </Section>
      </div>
    </Layout>
  )
}

export default BlogPostTemplate

export const query = graphql`
  query($slug: String!) {
    contentfulBlog: contentfulBlogPost(id: { eq: $slug }) {
      title
      tags
      date
      categories
      slug
      entryImage {
        fluid {
          base64
          aspectRatio
          src
          srcSet
          srcWebp
          srcSetWebp
          sizes
        }
      }
      body {
        id
        body
        childMarkdownRemark {
          html
        }
      }
    }

    allContentfulBlog: allContentfulBlogPost {
      edges {
        node {
          slug
        }
      }
    }
  }
`
