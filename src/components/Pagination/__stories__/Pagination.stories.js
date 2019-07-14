import React, { useState } from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Pagination from ".."

const blogs = [
  { title: "blog-1" },
  { title: "blog-2" },
  { title: "blog-3" },
  { title: "blog-4" },
  { title: "blog-5" },
  { title: "blog-6" },
  { title: "blog-7" },
  { title: "blog-8" },
  { title: "blog-9" },
  { title: "blog-10" },
  { title: "blog-11" },
  { title: "blog-12" },
]

// the pagination depends on the parent to have these states and function
const PostsWithPagi = () => {
  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(3)
  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage

  const paginate = pageNumber => setCurrentPage(pageNumber)
  return (
    <>
      {blogs.slice(indexOfFirstPost, indexOfLastPost).map(blog => (
        <p>{blog.title}</p>
      ))}
      <Pagination
        postsPerPage={postsPerPage}
        totalPosts={blogs.length}
        paginate={paginate}
        currentPage={currentPage}
      />
    </>
  )
}

storiesOf("Pagination", module)
  .addDecorator(jsxDecorator)
  .add("Parent holding Pagination", () => <PostsWithPagi />)
