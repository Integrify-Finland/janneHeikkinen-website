import React, { useState } from "react"
import { graphql } from "gatsby"
import { switchToNums, switchToCat } from "../../utilities/switches"
import Layout from "../../components/Layout"
import BlogItem from "../../components/BlogItem"
import SEO from "../../components/SEO"
import Pagination from "../../components/Pagination"
import Section from "../../components/Section"
import Sidebar from "../../components/Sidebar"
import image from "../../images/JANNE_HEIKKINEN_260619_77.jpg"
import { WP, WPContent } from "../../utilities/WPblogs.js"
import { selectImg } from "../../utilities/WPImages"
import { formatDate } from "../../utilities/FormatDate"
import "./styles.scss"


const Blogi = ({ data }) => {
  const { contentfulBlog } = data

  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(8)
  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage
  const paginate = pageNumber => {
    setCurrentPage(pageNumber)
    window.scrollTo(0, 0)
  }

  const allBlogs = [...contentfulBlog.edges, ...WPContent.edges]
  const [chosenBlogs, setChosenBlogs] = useState(allBlogs)


  const categories = WP.edges
    .map(({ node }) => {
      return node.categories.map(cat => switchToCat(cat))
    })
    .reduce((accumulator, currentValue) => {
      return accumulator.concat(currentValue)
    }, [])
    .filter((value, i, arr) => arr.indexOf(value) === i)
    .sort()

  const tags = WP.edges
    .filter(({ node }) => node.tags !== null)
    .reduce((acc, { node }) => {
      return [...acc, ...node.tags]
    }, [])
    .map(tags => tags.name)
    .filter((value, i, arr) => arr.indexOf(value) === i)
    .sort()

  const renderBlogs = (value, isCat) => {
    const filteredCat = allBlogs
      .map(({ node }) => ({
        node: {
          ...node,
          categories: node.categories.filter(
            cat => cat === switchToNums(value)
          ),
        },
      }))
      .filter(blog => blog.node.categories.length > 0)

      

    const filteredTag = allBlogs
      .map(({ node }) => {
        return {
          node: {
            ...node,
            tags:
              node.tags !== null && node.tags.filter(tag => tag.name === value),
          },
        }
      })
      .filter(blog => blog.node.tags.length > 0)
    isCat ? setChosenBlogs(filteredCat) : setChosenBlogs(filteredTag)
    setCurrentPage(1)
    window.scrollTo(0, 0)
  }

  return (
    <Layout>
      <SEO title="Blogit" />

      <div className="blogi-wrapper">
        <Sidebar
          blogs={allBlogs}
          image={image}
          categories={categories}
          tags={tags}
          renderBlogs={renderBlogs}
        />
        <Section>
          {chosenBlogs
            .map((blog, i) => ({
              blog,
              number: i + 1,
            }))
            .slice(indexOfFirstPost, indexOfLastPost)
            .map(({ blog, number }, index) => {
              const img = blog.node.entryImage
                ? blog.node.entryImage
                : selectImg(blog.node.id, image)
              const date = formatDate(blog.node.date)
   
              const text = blog.node.hasOwnProperty('childContentfulBlogPostContentRichTextNode') ? blog.node.childContentfulBlogPostContentRichTextNode.json : blog.node.content

              
              return (
                <BlogItem
                  isFluid={!!blog.node.entryImage}
                  date={date}
                  title={blog.node.title}
                  number={number}
                  image={img}
                  text={text}
                  isContentful={!!blog.node.entryImage}
                  link={`blogi/${blog.node.slug
                    .toLowerCase()
                    .replace(/[']/gi, "")
                    .replace(/ /gi, "-")
                    .replace(/[,]/gi, "")
                    .replace(/[ä]/gi, "a")
                    .replace(/[ö]/gi, "o")}`}
                />
              )
            })}

          <Pagination
            postsPerPage={postsPerPage}
            totalPosts={chosenBlogs.length}
            paginate={paginate}
            currentPage={currentPage}
          />
        </Section>
      </div>
    </Layout>
  )
}

export default Blogi

export const query = graphql`
  query {
    contentfulBlog: allContentfulBlogPost {
      edges {
        node {
          childContentfulBlogPostContentRichTextNode {
            json
          }
          title
          tags
          categories
         
          id
          slug
          date
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
        }
      }
    }
  }
`
