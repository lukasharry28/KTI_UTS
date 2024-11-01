using System;
using A07_UTS.Models;

namespace A07_UTS.Data;

public interface IStudent
{
    IEnumerable<Student> GetStudents();
    Student GetStudent(string nim);
    Student AddStudent(Student student);
    Student UpdateStudent(Student student);
    void DeleteStudent(string nim);
}
